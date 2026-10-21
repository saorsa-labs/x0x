//! ADR 0109 (S3 of ADR 0088): the daemon side of ownerless attestation,
//! stale-base self-recovery and manual re-seat.
//!
//! - §1 issuance: an admin answers `group_attest_request` after the cheap
//!   checks, in the ADR's order (verified sender, limits, classification,
//!   admin checks), and signs an ATA only for a head on its own chain.
//! - §2 self-recovery: the join carry (an ATA beside a stale joiner's
//!   served chain), the subject's request loop with the §11 backoff, and
//!   rule (b) (pre-Welcome link apply inside an armed attested sequence).
//!   An ATA acts only on its subject (D41).
//! - §3 manual re-seat: the admin's route, the signed authorisation, and
//!   the subject's journalled staged join and swap.
//! - §4 the `.grecov` sidecar; §6 guarded egress; §8 the `recovery` object.
//!
//! Pure wire types, limits and checks live in `crate::groups::recovery`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use tokio::time::Instant;

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::recovery::{
    self as s3, AdminTerminalAttestation, AtaFields, AttestAnswer, AttestRefusalReason,
    ChainPosition, GroupAttestRequestV1, GroupAttestResponseV1, GroupRecoveryDecodeError,
    GroupRecoveryMessageV1, GroupRecoveryV1, IssuedReseatV1, RecoveryRef, ReseatAuthorisation,
    ReseatAuthorisationFields, ReseatBasis, ReseatJournalV1, ReseatPhase, RetiredRecordV1,
};
use x0x::groups::state_commit::{GroupStateCommit, RetainedCommit};
use x0x::groups::GroupInfo;
use x0x::identity::AgentId;
use x0x::logging::LogHexId;

/// The worker tick.
const TICK: Duration = Duration::from_secs(2);
/// How long the subject waits for one target's answer before it asks the
/// next target in the round.
const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// The per-exchange bound of one guarded response write.
const RESPONSE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
/// The bound on the join carry's capability refresh for a joiner whose
/// advert is unknown or expired.
const JOIN_CARRY_CAPABILITY_WAIT: Duration = Duration::from_secs(3);
/// The grace past an authorisation's expiry before a staged join that has
/// not landed is abandoned (the join poll is 120 s).
const STAGING_GRACE: Duration = Duration::from_secs(150);

// ─── Runtime state ─────────────────────────────────────────────────────────

/// The S3 runtime held in `AppState`.
pub(in crate::server) struct S3Runtime {
    inner: tokio::sync::Mutex<S3Inner>,
    /// Serialises sidecar writes.
    writer: tokio::sync::Mutex<()>,
}

impl Default for S3Runtime {
    fn default() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(S3Inner::default()),
            writer: tokio::sync::Mutex::new(()),
        }
    }
}

#[derive(Default)]
struct S3Inner {
    /// Per group (stable ID): this node's own recovery as a subject.
    subjects: HashMap<String, SubjectState>,
    /// Per group (stable ID): the loaded sidecar.
    sidecars: HashMap<String, GroupRecoveryV1>,
    /// Per group (stable ID): a sidecar that cannot be used (§4).
    sidecar_status: HashMap<String, SidecarFault>,
    /// Per group (stable ID): the admin's bounded recovery list (§8).
    recovery_lists: HashMap<String, Vec<RecoveryListEntry>>,
    /// Per `(group, subject)`: the refs this admin answered `not_on_chain`
    /// for, or the subject reported as `attestation_conflict` (§3 basis).
    reseat_bases: HashMap<(String, String), Vec<RecoveryRef>>,
    /// The join carry: one ATA per `(attempt_id, from_revision)` (§2).
    join_carry: HashMap<(String, u64), AdminTerminalAttestation>,
    /// The §11 responder limits.
    responder: ResponderBudget,
    /// Groups (stable ID) whose staged join runs in this process. A journal
    /// with no live record and no entry here was interrupted by a restart.
    staging_live: HashSet<String>,
    /// The last `recovery` object per group (map key and stable ID), for
    /// the synchronous ADR 0066 §5 refusal body.
    recovery_cache: HashMap<String, serde_json::Value>,
    /// §1 step 2: signed ATAs keyed by `(group, subject, from_state_hash)`,
    /// reused until [`s3::ATA_ARM_WINDOW`] expires.
    ata_cache: HashMap<(String, String, String), AdminTerminalAttestation>,
}

/// A sidecar fault (§4, ADR 0108 §5a): S3 makes no transition for the
/// group while one holds.
#[derive(Debug, Clone)]
enum SidecarFault {
    Unavailable { file: String, cause: String },
    NewerFormat { file: String, version: u8 },
    QuarantineFailed { file: String, step: String },
}

/// One entry of an admin's recovery list (§8).
#[derive(Debug, Clone)]
struct RecoveryListEntry {
    requester: String,
    head_revision: u64,
    head_state_hash: String,
    refs: Vec<(RecoveryRef, String)>,
    answer: String,
    at: Instant,
    at_ms: u64,
}

/// The §11 responder limits.
#[derive(Default)]
struct ResponderBudget {
    per_requester: HashMap<[u8; 32], Instant>,
    window_start: Option<Instant>,
    signatures: u32,
    bytes: usize,
    building: usize,
}

impl ResponderBudget {
    fn roll(&mut self, now: Instant) {
        let fresh = self
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= Duration::from_secs(60));
        if fresh {
            self.window_start = Some(now);
            self.signatures = 0;
            self.bytes = 0;
        }
        self.per_requester.retain(|_, at| {
            now.saturating_duration_since(*at) < s3::RESPONDER_PER_REQUESTER_INTERVAL
        });
    }

    /// Admit one request from `requester`, or refuse it (§1 step 2).
    fn admit(&mut self, requester: [u8; 32], now: Instant) -> bool {
        self.roll(now);
        if self.per_requester.contains_key(&requester)
            || self.building >= s3::RESPONDER_CONCURRENT_BUILDS
            || self.bytes >= s3::RESPONDER_BYTES_PER_MINUTE
        {
            return false;
        }
        self.per_requester.insert(requester, now);
        self.building += 1;
        true
    }

    fn may_sign(&mut self) -> bool {
        if self.signatures >= s3::RESPONDER_SIGNATURES_PER_MINUTE {
            return false;
        }
        self.signatures += 1;
        true
    }

    fn finish(&mut self, bytes: usize) {
        self.building = self.building.saturating_sub(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// The subject's own recovery, per group.
#[derive(Debug, Clone)]
struct SubjectState {
    view: SubjectView,
    /// Rounds that ended with no usable answer (the backoff exponent).
    attempts: u32,
    next_retry_at: Instant,
    /// The index of the next target in the current round.
    next_target: usize,
    /// The target asked last, and when.
    pending: Option<([u8; 32], Instant)>,
    /// Each target asked and its last answer.
    asked: BTreeMap<String, String>,
    last_refusal: Option<String>,
    /// The state revision when this node last made progress; the gap
    /// trigger waits [`s3::GATE_STALL`] without progress.
    progress_revision: u64,
    progress_at: Instant,
}

impl SubjectState {
    fn new(now: Instant, revision: u64) -> Self {
        Self {
            view: SubjectView::Awaiting {
                reason: "no_reply".to_string(),
            },
            attempts: 0,
            next_retry_at: now,
            next_target: 0,
            pending: None,
            asked: BTreeMap::new(),
            last_refusal: None,
            progress_revision: revision,
            progress_at: now,
        }
    }

    fn end_round(&mut self, now: Instant) {
        self.attempts = self.attempts.saturating_add(1);
        self.next_retry_at = now + s3::request_backoff(self.attempts.saturating_sub(1));
        self.next_target = 0;
        self.pending = None;
    }
}

/// The §8 states this node holds for itself.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SubjectView {
    CatchingUp {
        attested_by: String,
        verified: bool,
        segment_terminal: u64,
    },
    Awaiting {
        reason: String,
    },
    Readmission {
        cause: &'static str,
    },
    ManualClear {
        recovery_ref: RecoveryRef,
    },
    Reseat {
        cause: &'static str,
        recovery_ref: Option<RecoveryRef>,
    },
    ReseatInProgress {
        authorised_by: String,
        phase: ReseatPhase,
        expires_at_ms: u64,
    },
    Deferred {
        cause: &'static str,
    },
    Refused {
        reason: &'static str,
    },
}

impl SubjectView {
    /// A sticky state that a later refusal or a plain retry does not
    /// replace: it waits for its own exit (§8).
    fn sticky(&self) -> bool {
        matches!(
            self,
            Self::Reseat { .. }
                | Self::ReseatInProgress { .. }
                | Self::ManualClear { .. }
                | Self::Refused { .. }
                | Self::Readmission { .. }
        )
    }
}

fn local_hex(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

fn now_ms() -> u64 {
    super::now_millis_u64()
}

/// ADR 0109 §4 (D81): a Home-policy group. Home activation ships off, so
/// S3 issues, requests and arms nothing for it.
fn is_home_policy_group(info: &GroupInfo) -> bool {
    info.home.is_some()
        || info
            .policy
            .admission
            .owner_certified_user_id()
            .is_some_and(|owner| crate::server::routes::home::is_home_candidate(info, owner))
}

/// The node's own record of the group is contained (§1 `attester_quarantined`,
/// §3 `admin_contained`): a marker, an owner-armed gap record, or an
/// admin-armed ATA.
async fn contained(state: &AppState, info: &GroupInfo) -> bool {
    info.fork_quarantine.is_some()
        || info
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
            .is_some_and(|record| {
                record.reason == s3::OWNER_ATTESTED_GAP_REASON
                    && info.state_revision < record.terminal_revision
            })
        || armed_admin_ata(state, info).await.is_some()
}

async fn agent_revoked(state: &AppState, agent: &AgentId) -> bool {
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    set.is_agent_revoked(agent)
}

/// D60 inputs at the write: the recipient's agent is not revoked, and
/// neither its advertised machine nor that agent-machine binding is.
async fn write_allowed(state: &AppState, agent: &AgentId) -> bool {
    let machine = state
        .agent
        .capability_store()
        .lookup_binding(agent)
        .map(|binding| binding.machine_id);
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    if set.is_agent_revoked(agent) {
        return false;
    }
    machine.is_none_or(|machine| {
        !set.is_machine_revoked(&machine) && !set.is_binding_revoked(agent, &machine)
    })
}

/// The recipient's current verified advert sets `group_terminal_attest_v1`.
/// Unknown or expired support asks for a refresh and counts as absent.
fn peer_capable(state: &Arc<AppState>, agent: &AgentId) -> Option<bool> {
    let supported = state
        .agent
        .capability_store()
        .verified_registry_supports(agent, x0x::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1);
    if supported.is_none() {
        let task_state = Arc::clone(state);
        let agent = *agent;
        let _spawned = state.spawn_detached(async move {
            task_state
                .agent
                .refresh_application_capability(
                    agent,
                    x0x::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1,
                )
                .await;
        });
    }
    supported
}

// ─── §4 Sidecar IO ─────────────────────────────────────────────────────────

fn sidecar_dir(state: &AppState) -> PathBuf {
    state.data_dir.join(s3::GROUP_RECOVERY_DIR)
}

fn sidecar_path(state: &AppState, stable_group_id: &str) -> PathBuf {
    sidecar_dir(state).join(s3::sidecar_file_name(stable_group_id))
}

/// Write one group's sidecar durably, or remove it when empty. Returns
/// whether the bytes are durable.
async fn write_sidecar(state: &AppState, stable_group_id: &str, body: &GroupRecoveryV1) -> bool {
    let path = sidecar_path(state, stable_group_id);
    if body.is_empty() {
        return match tokio::fs::remove_file(&path).await {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "ADR 0109 S3: cannot remove an empty sidecar");
                false
            }
        };
    }
    if let Err(error) = tokio::fs::create_dir_all(sidecar_dir(state)).await {
        tracing::warn!(%error, "ADR 0109 S3: cannot create the group-recovery directory");
        return false;
    }
    let bytes = match s3::encode_sidecar(body) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "ADR 0109 S3: cannot encode the sidecar");
            return false;
        }
    };
    match super::revocation_eviction::write_bytes_durably(&path, &bytes, None).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "ADR 0109 S3: sidecar write failed");
            false
        }
    }
}

/// Apply `mutate` to one group's sidecar and write it durably (§4: every
/// transition carries `generation + 1`). Returns `false`, with memory
/// unchanged, when the group's sidecar has a fault or the write is not
/// durable.
async fn update_sidecar<F>(state: &AppState, stable_group_id: &str, mutate: F) -> bool
where
    F: FnOnce(&mut GroupRecoveryV1),
{
    let runtime = &state.group_recovery;
    let _writer = runtime.writer.lock().await;
    let mut candidate = {
        let inner = runtime.inner.lock().await;
        if inner.sidecar_status.contains_key(stable_group_id) {
            return false;
        }
        inner
            .sidecars
            .get(stable_group_id)
            .cloned()
            .unwrap_or_default()
    };
    mutate(&mut candidate);
    candidate.generation = candidate.generation.saturating_add(1);
    if !write_sidecar(state, stable_group_id, &candidate).await {
        return false;
    }
    let mut inner = runtime.inner.lock().await;
    if candidate.is_empty() {
        inner.sidecars.remove(stable_group_id);
    } else {
        inner
            .sidecars
            .insert(stable_group_id.to_string(), candidate);
    }
    true
}

async fn sidecar_snapshot(state: &AppState, stable_group_id: &str) -> Option<GroupRecoveryV1> {
    state
        .group_recovery
        .inner
        .lock()
        .await
        .sidecars
        .get(stable_group_id)
        .cloned()
}

/// Load every `.grecov` file at worker start (§4). A damaged file is moved
/// aside by the ADR 0108 §5a quarantine and replaced by an empty rebuild;
/// a newer-format file stays in place and its group is memory-only.
async fn load_sidecars(state: &AppState) {
    let dir = sidecar_dir(state);
    let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
        return;
    };
    let mut loaded = HashMap::new();
    let mut faults = HashMap::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let Some(stem) = name.strip_suffix(&format!(".{}", s3::GROUP_RECOVERY_EXTENSION)) else {
            continue;
        };
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) => {
                faults.insert(
                    stem.to_string(),
                    SidecarFault::Unavailable {
                        file: name.clone(),
                        cause: error.kind().to_string(),
                    },
                );
                continue;
            }
        };
        match s3::decode_sidecar(&bytes) {
            Ok(body) => {
                loaded.insert(stem.to_string(), body);
            }
            Err(GroupRecoveryDecodeError::NewerFormat(version)) => {
                faults.insert(
                    stem.to_string(),
                    SidecarFault::NewerFormat {
                        file: name.clone(),
                        version,
                    },
                );
            }
            Err(GroupRecoveryDecodeError::Damaged(cause)) => {
                tracing::warn!(file = %name, cause, "ADR 0109 S3: damaged sidecar; quarantining (D120)");
                match super::revocation_eviction::quarantine_file(&path, &bytes).await {
                    Ok((txid, pending)) => {
                        let rebuilt = GroupRecoveryV1 {
                            generation: 1,
                            rebuilt_from: vec![txid],
                            ..GroupRecoveryV1::default()
                        };
                        if write_sidecar_rebuild(&path, &rebuilt).await {
                            let _ = super::revocation_eviction::finalize_quarantine(&pending).await;
                            loaded.insert(stem.to_string(), rebuilt);
                        } else {
                            faults.insert(
                                stem.to_string(),
                                SidecarFault::QuarantineFailed {
                                    file: name.clone(),
                                    step: "rebuild".to_string(),
                                },
                            );
                        }
                    }
                    Err(step) => {
                        faults.insert(
                            stem.to_string(),
                            SidecarFault::QuarantineFailed {
                                file: name.clone(),
                                step: step.to_string(),
                            },
                        );
                    }
                }
            }
        }
    }
    let mut inner = state.group_recovery.inner.lock().await;
    // Files are named by the sanitised stable ID; map them back through
    // the live groups so the in-memory key is the stable ID itself.
    let groups = state.named_groups.read().await;
    for info in groups.values() {
        let stable = info.stable_group_id();
        let file = s3::sidecar_file_name(stable);
        let stem = file
            .strip_suffix(&format!(".{}", s3::GROUP_RECOVERY_EXTENSION))
            .unwrap_or(&file)
            .to_string();
        if let Some(body) = loaded.remove(&stem) {
            inner.sidecars.insert(stable.to_string(), body);
        }
        if let Some(fault) = faults.remove(&stem) {
            inner.sidecar_status.insert(stable.to_string(), fault);
        }
    }
    // A sidecar whose group is not in the live map holds a re-seat journal
    // (the live record was moved aside): keep it by its file stem, which is
    // the stable ID for every well-formed ID.
    for (stem, body) in loaded {
        if body.reseat_journal.is_some() {
            inner.sidecars.insert(stem, body);
        }
    }
}

async fn write_sidecar_rebuild(path: &FsPath, body: &GroupRecoveryV1) -> bool {
    match s3::encode_sidecar(body) {
        Ok(bytes) => super::revocation_eviction::write_bytes_durably(path, &bytes, None)
            .await
            .is_ok(),
        Err(_) => false,
    }
}

// ─── §6 Guarded egress ─────────────────────────────────────────────────────

/// Which serving guard one response write uses (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    /// ADR 0107's serving guard plus D60: an Active, unbanned, unrevoked
    /// member of a group that is not withdrawn or quarantined.
    Member,
    /// The re-seat guard: not Active, not banned or revoked, holding a
    /// current unconsumed authorisation, plus D60.
    Reseat,
    /// A refusal carries no group state: D60 only.
    Refusal,
}

fn admission(
    state: &Arc<AppState>,
    group_key: &str,
    recipient: AgentId,
    guard: Guard,
) -> x0x::dm::ArtifactAdmission {
    let state = Arc::clone(state);
    let group_key = group_key.to_string();
    Arc::new(move || {
        let state = Arc::clone(&state);
        let group_key = group_key.clone();
        Box::pin(async move {
            let recipient_hex = hex::encode(recipient.as_bytes());
            let lock = super::group_membership_lock_for_known_group(&state, &group_key).await?;
            let evidence = {
                let _membership_guard = lock.lock().await;
                if !write_allowed(&state, &recipient).await {
                    return None;
                }
                match guard {
                    Guard::Member => {
                        super::join_artifact_serving_check(&state, &group_key, &recipient_hex)
                            .await
                            .ok()?
                    }
                    Guard::Reseat => {
                        let info = state.named_groups.read().await.get(&group_key).cloned()?;
                        if info.withdrawn
                            || info.has_active_member(&recipient_hex)
                            || info.is_banned(&recipient_hex)
                            || !issued_reseat_current(
                                &state,
                                info.stable_group_id(),
                                &recipient_hex,
                            )
                            .await
                        {
                            return None;
                        }
                        None
                    }
                    Guard::Refusal => None,
                }
            };
            let seam: x0x::dm::SeamAdmission = match guard {
                Guard::Member => Box::new(move || {
                    super::join_artifact_seam_refusal(&state, &group_key, &recipient_hex, evidence)
                        .is_none()
                }),
                Guard::Reseat => Box::new(move || {
                    state.named_groups.try_read().is_ok_and(|groups| {
                        groups.get(&group_key).is_some_and(|info| {
                            !info.withdrawn
                                && !info.has_active_member(&recipient_hex)
                                && !info.is_banned(&recipient_hex)
                        })
                    })
                }),
                Guard::Refusal => Box::new(|| true),
            };
            Some(seam)
        })
    })
}

/// Send one response in one admitted exchange (§6: no hidden resend, no
/// gossip fallback).
async fn guarded_send(
    state: &Arc<AppState>,
    group_key: &str,
    recipient: AgentId,
    guard: Guard,
    payload: &[u8],
) -> bool {
    let admission = admission(state, group_key, recipient, guard);
    let resolve_within = std::cmp::min(
        x0x::dm::PINNED_RESOLUTION_WAIT,
        RESPONSE_EXCHANGE_TIMEOUT / 2,
    );
    let exchange =
        state
            .agent
            .send_direct_pinned_admitted(&recipient, payload, &admission, resolve_within);
    match tokio::time::timeout(RESPONSE_EXCHANGE_TIMEOUT, exchange).await {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            tracing::debug!(%error, "ADR 0109 S3: response write refused or failed");
            false
        }
        Err(_) => {
            tracing::debug!("ADR 0109 S3: response exchange deadline elapsed");
            false
        }
    }
}

async fn issued_reseat_current(state: &AppState, stable_group_id: &str, subject_hex: &str) -> bool {
    let now = now_ms();
    state
        .group_recovery
        .inner
        .lock()
        .await
        .sidecars
        .get(stable_group_id)
        .is_some_and(|body| {
            body.issued_reseats.iter().any(|issued| {
                issued
                    .authorisation
                    .fields
                    .subject
                    .eq_ignore_ascii_case(subject_hex)
                    && issued.authorisation.fields.expires_at_ms > now
            })
        })
}

// ─── Receive ───────────────────────────────────────────────────────────────

/// The direct-message listener hands every `X0XGRC1` payload here.
pub(in crate::server) fn spawn_receipt(
    state: &Arc<AppState>,
    sender: AgentId,
    verified: bool,
    payload: Vec<u8>,
) {
    if !verified {
        return;
    }
    let task_state = Arc::clone(state);
    let _spawned = state.spawn_detached(async move {
        match s3::decode_message(&payload) {
            Ok(GroupRecoveryMessageV1::Request(request)) => {
                answer_request(&task_state, sender, request).await;
            }
            Ok(GroupRecoveryMessageV1::Response(response)) => {
                handle_response(&task_state, sender, response).await;
            }
            Err(refusal) => {
                tracing::debug!(
                    reason = refusal.as_str(),
                    "ADR 0109 S3: recovery frame refused"
                );
            }
        }
    });
}

// ─── §1 Issuance (the admin side) ──────────────────────────────────────────

async fn answer_request(state: &Arc<AppState>, sender: AgentId, request: GroupAttestRequestV1) {
    // Step 1: the DM is verified (checked by the caller) and its sender is
    // the requester.
    if sender.as_bytes() != &request.requester {
        return;
    }
    let Some(group_key) = super::resolve_named_group_storage_key(state, &request.group).await
    else {
        return;
    };
    // §4 (D81): Home activation (issuing an ATA for a Home-policy group)
    // ships off, and a Home subject never asks; S3 answers nothing there.
    let home = state
        .named_groups
        .read()
        .await
        .get(&group_key)
        .is_some_and(is_home_policy_group);
    if home {
        return;
    }
    // Step 2: limits, before anything else.
    let now = Instant::now();
    let admitted = state
        .group_recovery
        .inner
        .lock()
        .await
        .responder
        .admit(request.requester, now);
    if !admitted {
        let response = response_for(
            &request,
            AttestAnswer::Refused(AttestRefusalReason::RateLimited),
        );
        send_response(state, &group_key, sender, Guard::Refusal, &response, false).await;
        return;
    }
    let (answer, guard) = build_answer(state, &group_key, &request).await;
    let response = response_for(&request, answer);
    let bytes = send_response(state, &group_key, sender, guard, &response, true).await;
    state
        .group_recovery
        .inner
        .lock()
        .await
        .responder
        .finish(bytes);
}

fn response_for(request: &GroupAttestRequestV1, answer: AttestAnswer) -> GroupAttestResponseV1 {
    GroupAttestResponseV1 {
        group: request.group.clone(),
        subject: request.requester,
        for_head_state_hash: request.head_state_hash.clone(),
        answer,
    }
}

/// Encode and send one response; returns the bytes sent.
async fn send_response(
    state: &Arc<AppState>,
    group_key: &str,
    recipient: AgentId,
    guard: Guard,
    response: &GroupAttestResponseV1,
    log: bool,
) -> usize {
    let payload = match s3::encode_message(&GroupRecoveryMessageV1::Response(response.clone())) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, "ADR 0109 S3: cannot encode a response");
            return 0;
        }
    };
    if payload.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        tracing::warn!(
            len = payload.len(),
            "ADR 0109 S3: response exceeds the direct-message budget; not sent"
        );
        return 0;
    }
    let sent = guarded_send(state, group_key, recipient, guard, &payload).await;
    if log {
        tracing::info!(
            group_id = %LogHexId::group(group_key),
            requester = %LogHexId::agent(&hex::encode(recipient.as_bytes())),
            answer = response.answer.name(),
            sent,
            "ADR 0109 S3: answered group_attest_request"
        );
    }
    if sent {
        payload.len()
    } else {
        0
    }
}

/// §1 steps 3 onward, under the group's membership lock.
async fn build_answer(
    state: &Arc<AppState>,
    group_key: &str,
    request: &GroupAttestRequestV1,
) -> (AttestAnswer, Guard) {
    let lock = super::group_membership_lock(state, group_key).await;
    let _membership_guard = lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(group_key).cloned() else {
        return (
            AttestAnswer::Refused(AttestRefusalReason::NotAMember),
            Guard::Refusal,
        );
    };
    let stable = info.stable_group_id().to_string();
    let requester = AgentId(request.requester);
    let requester_hex = hex::encode(request.requester);
    let local = local_hex(state);
    // Step 3: classification.
    let (answer, guard) =
        if info.is_banned(&requester_hex) || agent_revoked(state, &requester).await {
            (
                AttestAnswer::Refused(AttestRefusalReason::BannedOrRevoked),
                Guard::Refusal,
            )
        } else if !info.has_active_member(&requester_hex) {
            match current_issued_reseat(state, &stable, &requester_hex).await {
                Some(issued) => (
                    AttestAnswer::Reseat {
                        authorisation: Box::new(issued.authorisation),
                        invite: issued.invite,
                    },
                    Guard::Reseat,
                ),
                None => (
                    AttestAnswer::Refused(AttestRefusalReason::NotAMember),
                    Guard::Refusal,
                ),
            }
        } else if !s3::signer_is_active_admin(&info, &local) {
            (
                AttestAnswer::Refused(AttestRefusalReason::NotAnAdmin),
                Guard::Member,
            )
        } else if contained(state, &info).await {
            (
                AttestAnswer::Refused(AttestRefusalReason::AttesterQuarantined),
                Guard::Member,
            )
        } else {
            let head = s3::AdminHead {
                revision: info.state_revision,
                state_hash: info.state_hash.clone(),
            };
            match s3::chain_position(&info, request.head_revision, &request.head_state_hash) {
                ChainPosition::Behind {
                    sequence,
                    terminal_revision,
                } => match sign_ata(
                    state,
                    &info,
                    &requester_hex,
                    request,
                    sequence,
                    terminal_revision,
                )
                .await
                {
                    Some(ata) => (AttestAnswer::Attested(Box::new(ata)), Guard::Member),
                    None => (
                        AttestAnswer::Refused(AttestRefusalReason::RateLimited),
                        Guard::Member,
                    ),
                },
                ChainPosition::OnChain => (AttestAnswer::OnChain(head), Guard::Member),
                ChainPosition::NotOnChain => {
                    remember_reseat_bases(state, &stable, &requester_hex, request, true).await;
                    (AttestAnswer::NotOnChain(head), Guard::Member)
                }
                ChainPosition::AttesterBehind => (
                    AttestAnswer::Refused(AttestRefusalReason::AttesterBehind),
                    Guard::Member,
                ),
                ChainPosition::BeyondRetention => (
                    AttestAnswer::Refused(AttestRefusalReason::BaseBeyondRetention),
                    Guard::Member,
                ),
            }
        };
    remember_reseat_bases(state, &stable, &requester_hex, request, false).await;
    record_recovery_list(state, &stable, &requester_hex, request, answer.name()).await;
    (answer, guard)
}

async fn sign_ata(
    state: &AppState,
    info: &GroupInfo,
    subject_hex: &str,
    request: &GroupAttestRequestV1,
    sequence: Vec<String>,
    terminal_revision: u64,
) -> Option<AdminTerminalAttestation> {
    let cache_key = (
        info.stable_group_id().to_string(),
        subject_hex.to_string(),
        request.head_state_hash.clone(),
    );
    let window = u64::try_from(s3::ATA_ARM_WINDOW.as_millis()).unwrap_or(u64::MAX);
    {
        let mut inner = state.group_recovery.inner.lock().await;
        let now = now_ms();
        inner
            .ata_cache
            .retain(|_, ata| now.saturating_sub(ata.fields.issued_at_ms) < window);
        if let Some(cached) = inner.ata_cache.get(&cache_key) {
            return Some(cached.clone());
        }
        if !inner.responder.may_sign() {
            return None;
        }
    }
    let epoch = info
        .commit_log
        .iter()
        .find(|entry| entry.commit.revision == terminal_revision)
        .and_then(|entry| s3::treekem_epoch_of(&entry.commit));
    let keypair = state.agent.identity().agent_keypair();
    let fields = AtaFields {
        group: info.stable_group_id().to_string(),
        subject: subject_hex.to_string(),
        attested_by: local_hex(state),
        signer_public_key: hex::encode(keypair.public_key().as_bytes()),
        from_revision: request.head_revision,
        from_state_hash: request.head_state_hash.clone(),
        sequence,
        segment_terminal_revision: terminal_revision,
        segment_terminal_epoch: epoch,
        issued_at_ms: now_ms(),
    };
    let ata = AdminTerminalAttestation::sign(fields, keypair).ok()?;
    let mut inner = state.group_recovery.inner.lock().await;
    if inner.ata_cache.len() >= 256 {
        inner.ata_cache.clear();
    }
    inner.ata_cache.insert(cache_key, ata.clone());
    Some(ata)
}

async fn current_issued_reseat(
    state: &AppState,
    stable_group_id: &str,
    subject_hex: &str,
) -> Option<IssuedReseatV1> {
    let now = now_ms();
    state
        .group_recovery
        .inner
        .lock()
        .await
        .sidecars
        .get(stable_group_id)?
        .issued_reseats
        .iter()
        .find(|issued| {
            issued
                .authorisation
                .fields
                .subject
                .eq_ignore_ascii_case(subject_hex)
                && issued.authorisation.fields.expires_at_ms > now
        })
        .cloned()
}

/// Keep the refs a re-seat may name as its basis (§3): every ref of a
/// request this admin answers `not_on_chain`, and every ref the subject
/// reports as `attestation_conflict`.
async fn remember_reseat_bases(
    state: &AppState,
    stable_group_id: &str,
    subject_hex: &str,
    request: &GroupAttestRequestV1,
    not_on_chain: bool,
) {
    let refs: Vec<RecoveryRef> = request
        .refs
        .iter()
        .filter(|(_, cause)| not_on_chain || cause == "attestation_conflict")
        .map(|(recovery_ref, _)| recovery_ref.clone())
        .collect();
    if refs.is_empty() {
        return;
    }
    let mut inner = state.group_recovery.inner.lock().await;
    let entry = inner
        .reseat_bases
        .entry((stable_group_id.to_string(), subject_hex.to_string()))
        .or_default();
    for recovery_ref in refs {
        if !entry.contains(&recovery_ref) {
            entry.push(recovery_ref);
        }
    }
    let excess = entry.len().saturating_sub(s3::RECOVERY_LIST_CAP);
    entry.drain(..excess);
}

async fn record_recovery_list(
    state: &AppState,
    stable_group_id: &str,
    requester_hex: &str,
    request: &GroupAttestRequestV1,
    answer: &str,
) {
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    let list = inner
        .recovery_lists
        .entry(stable_group_id.to_string())
        .or_default();
    list.retain(|entry| {
        entry.requester != requester_hex
            && now.saturating_duration_since(entry.at) < s3::RECOVERY_LIST_TTL
    });
    list.push(RecoveryListEntry {
        requester: requester_hex.to_string(),
        head_revision: request.head_revision,
        head_state_hash: request.head_state_hash.clone(),
        refs: request.refs.clone(),
        answer: answer.to_string(),
        at: now,
        at_ms: now_ms(),
    });
    let excess = list.len().saturating_sub(s3::RECOVERY_LIST_CAP);
    list.drain(..excess);
}

// ─── §2 The join carry ─────────────────────────────────────────────────────

/// The authority's join-carry ATA for the first segment of a stale
/// joiner's served chain (§2 "Join carry"). `None` unless every condition
/// holds: a non-empty served chain linking from the joiner's base, no
/// owner v2 attestation served, the joiner's current verified advert sets
/// the §5 bit, this node an uncontained active admin, and the group not
/// Home-policy (Home activation is off). One signature per
/// `(attempt_id, from_revision)`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn join_carry_attestation(
    state: &Arc<AppState>,
    group_key: &str,
    member_hex: &str,
    from_revision: Option<u64>,
    base_state_hash: Option<&str>,
    chain: &[RetainedCommit],
    terminal: Option<&GroupStateCommit>,
    terminal_epoch: Option<u64>,
    attempt_id: Option<&str>,
    owner_terminal_served: bool,
) -> Option<AdminTerminalAttestation> {
    let (Some(from_revision), Some(base_state_hash), Some(terminal), Some(attempt_id)) =
        (from_revision, base_state_hash, terminal, attempt_id)
    else {
        return None;
    };
    if owner_terminal_served || chain.is_empty() {
        return None;
    }
    if chain
        .first()
        .and_then(|link| link.commit.prev_state_hash.as_deref())
        != Some(base_state_hash)
    {
        return None;
    }
    let member = x0x::identity::AgentId(parse_raw(member_hex)?);
    let bit = x0x::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1;
    let mut supported = state
        .agent
        .capability_store()
        .verified_registry_supports(&member, bit);
    if supported.is_none() {
        // Unknown or expired support first asks for an authenticated
        // advert refresh (ADR 0093), bounded so the fetch is not stalled.
        let _ = tokio::time::timeout(
            JOIN_CARRY_CAPABILITY_WAIT,
            state.agent.refresh_application_capability(member, bit),
        )
        .await;
        supported = state
            .agent
            .capability_store()
            .verified_registry_supports(&member, bit);
    }
    if supported != Some(true) {
        return None;
    }
    let info = state.named_groups.read().await.get(group_key).cloned()?;
    let local = local_hex(state);
    if is_home_policy_group(&info)
        || !s3::signer_is_active_admin(&info, &local)
        || contained(state, &info).await
    {
        return None;
    }
    let cache_key = (attempt_id.to_string(), from_revision);
    if let Some(cached) = state
        .group_recovery
        .inner
        .lock()
        .await
        .join_carry
        .get(&cache_key)
        .cloned()
    {
        return Some(cached);
    }
    let mut sequence: Vec<String> = chain
        .iter()
        .map(|link| link.commit.state_hash.clone())
        .chain(std::iter::once(terminal.state_hash.clone()))
        .collect();
    sequence.truncate(s3::ATA_MAX_LINKS);
    let segment_terminal_revision = from_revision.saturating_add(sequence.len() as u64);
    let segment_terminal_epoch = if segment_terminal_revision == terminal.revision {
        terminal_epoch
    } else {
        chain
            .iter()
            .find(|link| link.commit.revision == segment_terminal_revision)
            .and_then(|link| s3::treekem_epoch_of(&link.commit))
    };
    let keypair = state.agent.identity().agent_keypair();
    let fields = AtaFields {
        group: info.stable_group_id().to_string(),
        subject: member_hex.to_ascii_lowercase(),
        attested_by: local,
        signer_public_key: hex::encode(keypair.public_key().as_bytes()),
        from_revision,
        from_state_hash: base_state_hash.to_string(),
        sequence,
        segment_terminal_revision,
        segment_terminal_epoch,
        issued_at_ms: now_ms(),
    };
    let ata = AdminTerminalAttestation::sign(fields, keypair).ok()?;
    let mut inner = state.group_recovery.inner.lock().await;
    if inner.join_carry.len() >= 256 {
        inner.join_carry.clear();
    }
    inner.join_carry.insert(cache_key, ata.clone());
    Some(ata)
}

fn parse_raw(hex_id: &str) -> Option<[u8; 32]> {
    let mut raw = [0u8; 32];
    hex::decode_to_slice(hex_id, &mut raw).ok()?;
    Some(raw)
}

/// The joiner's side of the join carry (§2): verify the ATA against this
/// node's head, walk the served chain, arm the gate with reason
/// `admin_attested_stale_base_gap`, and apply each attested link
/// state-only while pre-Welcome (rule (b)). The caller then applies its
/// own terminal, which now chains. Returns whether the chain applied.
pub(super) async fn apply_join_carry(
    state: &Arc<AppState>,
    group_id: &str,
    chain: &[RetainedCommit],
    terminal: &GroupStateCommit,
    ata: &AdminTerminalAttestation,
) -> bool {
    let Some(group_key) = super::resolve_named_group_storage_key(state, group_id).await else {
        return false;
    };
    let lock = super::group_membership_lock(state, &group_key).await;
    let _membership_guard = lock.lock().await;
    let Some(current) = state.named_groups.read().await.get(&group_key).cloned() else {
        return false;
    };
    let local = local_hex(state);
    let stable = current.stable_group_id().to_string();
    if is_home_policy_group(&current) {
        set_view(
            state,
            &stable,
            current.state_revision,
            SubjectView::Deferred {
                cause: "home_gate_closed",
            },
        )
        .await;
        return false;
    }
    let signer_revoked = match parse_raw(&ata.fields.attested_by) {
        Some(raw) => agent_revoked(state, &AgentId(raw)).await,
        None => true,
    };
    if let Err(refusal) = ata.verify_for_subject(
        &stable,
        &local,
        current.state_revision,
        &current.state_hash,
        now_ms(),
        signer_revoked,
    ) {
        tracing::info!(group_id = %LogHexId::group(&group_key), reason = refusal.as_str(), "ADR 0109 S3: join-carry ATA refused");
        return false;
    }
    let pre_welcome = !current.has_active_member(&local)
        && !state.treekem_groups.read().await.contains_key(&group_key);
    if !pre_welcome {
        return false;
    }
    let base = x0x::groups::state_commit::AlternateChainBase {
        group_id: current.stable_group_id(),
        base_revision: current.state_revision,
        base_state_hash: &current.state_hash,
        roster: &x0x::groups::state_commit::roster_projection(&current.members_v2),
        meta: &current.public_meta(),
        policy_hash: &x0x::groups::compute_policy_hash(&current.policy),
    };
    if let Err(reason) = x0x::groups::state_commit::validate_alternate_chain(&base, chain, terminal)
    {
        tracing::info!(group_id = %LogHexId::group(&group_key), reason, "ADR 0109 S3: join-carry served chain does not walk from this head");
        return false;
    }
    let served: Vec<String> = chain
        .iter()
        .map(|link| link.commit.state_hash.clone())
        .chain(std::iter::once(terminal.state_hash.clone()))
        .collect();
    if !ata.agrees_with(&served) {
        // Two answers for one head that diverge: a conflict (§2).
        set_view(
            state,
            &stable,
            current.state_revision,
            SubjectView::Reseat {
                cause: "attestation_conflict",
                recovery_ref: RecoveryRef::live_refs(&current).into_iter().next(),
            },
        )
        .await;
        return false;
    }
    // Signer eligibility: verified on this node's roster, or provisional
    // with a promotion path inside the walked served chain.
    let verified = ata.signer_verified_on(&current);
    let armed_from = if verified {
        0
    } else {
        match s3::promotion_prefix(ata, chain) {
            Some(prefix) => prefix,
            None => {
                set_view(
                    state,
                    &stable,
                    current.state_revision,
                    SubjectView::Awaiting {
                        reason: "provisional_unverified".to_string(),
                    },
                )
                .await;
                return false;
            }
        }
    };
    // An owner-attested record keeps precedence; an armed record is never
    // re-armed by an ATA.
    let owner_armed = current
        .invite_lineage
        .as_ref()
        .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
        .is_some_and(|record| {
            record.reason == s3::OWNER_ATTESTED_GAP_REASON
                && current.state_revision < record.terminal_revision
        });
    if owner_armed || armed_admin_ata(state, &current).await.is_some() {
        return false;
    }
    // The armed admin record lives in the S3 sidecar (`active_ata`), never
    // in the legacy JSON stores, so a released binary never loads an armed
    // admin record it does not honour (§4).
    let mut next = current.clone();
    // Rule (b): every attested link before the terminal, state-only. A
    // provisional signer's promotion prefix (`armed_from` links) was walked
    // above with every committer checked against its predecessor roster;
    // it is applied the same way, because the joiner's terminal chains
    // only through it.
    if armed_from > 0 {
        tracing::info!(group_id = %LogHexId::group(&group_key), armed_from, "ADR 0109 S3: provisional signer verified by its promotion path in the served chain");
    }
    let segment_links = ata.fields.sequence.len().min(chain.len());
    for link in chain.iter().take(segment_links) {
        match s3::apply_link_state_only(&next, link) {
            Ok(applied) => next = applied,
            Err(reason) => {
                tracing::info!(group_id = %LogHexId::group(&group_key), reason, revision = link.commit.revision, "ADR 0109 S3: attested link refused");
                return false;
            }
        }
    }
    // Keep the served chain and the ATA beside the record (§4).
    let served_json: Vec<Vec<u8>> = chain
        .iter()
        .filter_map(|link| serde_json::to_vec(link).ok())
        .collect();
    let ata_kept = ata.clone();
    let terminal_json = serde_json::to_vec(terminal).ok();
    if !update_sidecar(state, &stable, move |body| {
        body.served_chain = served_json;
        body.active_ata = Some(ata_kept);
        body.queued_terminal = terminal_json;
    })
    .await
    {
        tracing::warn!(group_id = %LogHexId::group(&group_key), "ADR 0109 S3: sidecar not durable; join carry not applied");
        return false;
    }
    match super::persist_named_group_info(state, &group_key, next.clone()).await {
        Ok(super::AtomicWriteOutcome::Durable) => {}
        _ => {
            tracing::warn!(group_id = %LogHexId::group(&group_key), "ADR 0109 S3: attested links not durable");
            return false;
        }
    }
    set_view(
        state,
        &stable,
        next.state_revision,
        SubjectView::CatchingUp {
            attested_by: ata.fields.attested_by.clone(),
            verified,
            segment_terminal: ata.fields.segment_terminal_revision,
        },
    )
    .await;
    tracing::info!(
        group_id = %LogHexId::group(&group_key),
        attested_by = %LogHexId::agent(&ata.fields.attested_by),
        from = current.state_revision,
        to = next.state_revision,
        "ADR 0109 S3: stale-base join catching up under an admin terminal attestation"
    );
    true
}

/// §2: keep a pre-Welcome joiner's walk-valid served chain and its refused
/// terminal event in the sidecar (once per terminal), so a later verified
/// ATA from the request path can apply them under rule (b).
pub(super) async fn keep_served_chain(
    state: &AppState,
    current: &GroupInfo,
    terminal: &GroupStateCommit,
    chain: &[RetainedCommit],
    terminal_event: &super::NamedGroupMetadataEvent,
) {
    let local = local_hex(state);
    if current.has_active_member(&local) {
        return;
    }
    let base = x0x::groups::state_commit::AlternateChainBase {
        group_id: current.stable_group_id(),
        base_revision: current.state_revision,
        base_state_hash: &current.state_hash,
        roster: &x0x::groups::state_commit::roster_projection(&current.members_v2),
        meta: &current.public_meta(),
        policy_hash: &x0x::groups::compute_policy_hash(&current.policy),
    };
    if x0x::groups::state_commit::validate_alternate_chain(&base, chain, terminal).is_err() {
        return;
    }
    let Ok(event_json) = serde_json::to_vec(terminal_event) else {
        return;
    };
    let stable = current.stable_group_id().to_string();
    let already = sidecar_snapshot(state, &stable)
        .await
        .and_then(|body| body.queued_terminal)
        .is_some_and(|kept| kept == event_json);
    if already {
        return;
    }
    let served_json: Vec<Vec<u8>> = chain
        .iter()
        .filter_map(|link| serde_json::to_vec(link).ok())
        .collect();
    let _ = update_sidecar(state, &stable, move |body| {
        body.served_chain = served_json;
        body.queued_terminal = Some(event_json);
    })
    .await;
}

/// §2: a verified ATA from the request path for a pre-Welcome joiner that
/// kept its served chain and terminal: apply the attested links under rule
/// (b), then replay the kept terminal through the ordinary apply path.
/// Returns whether the terminal was replayed.
async fn apply_kept_chain(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    ata: &AdminTerminalAttestation,
) -> bool {
    let Some(body) = sidecar_snapshot(state, info.stable_group_id()).await else {
        return false;
    };
    let Some(event_json) = body.queued_terminal else {
        return false;
    };
    let Ok(event) = serde_json::from_slice::<super::NamedGroupMetadataEvent>(&event_json) else {
        return false;
    };
    let chain: Vec<RetainedCommit> = body
        .served_chain
        .iter()
        .filter_map(|bytes| serde_json::from_slice(bytes).ok())
        .collect();
    let (Some(terminal), Some(actor)) = (
        super::named_group_metadata_event_commit(&event).cloned(),
        match &event {
            super::NamedGroupMetadataEvent::MemberAdded { actor, .. } => parse_raw(actor),
            _ => None,
        },
    ) else {
        return false;
    };
    if chain.is_empty()
        || !Box::pin(apply_join_carry(state, group_key, &chain, &terminal, ata)).await
    {
        return false;
    }
    let accepted = Box::pin(super::apply_named_group_metadata_event(
        state,
        event,
        AgentId(actor),
        true,
        None,
    ))
    .await
    .accepted;
    retire_converged(state, group_key).await;
    accepted
}

/// The armed admin ATA of `info` (§2 "Arming"): the sidecar's active ATA
/// while this node's head is on its sequence (or is its `from`) and its
/// segment terminal is not yet reached.
pub(super) async fn armed_admin_ata(
    state: &AppState,
    info: &GroupInfo,
) -> Option<AdminTerminalAttestation> {
    let ata = sidecar_snapshot(state, info.stable_group_id())
        .await?
        .active_ata?;
    let on_sequence = info.state_hash == ata.fields.from_state_hash
        || ata.fields.sequence.contains(&info.state_hash);
    (on_sequence && info.state_revision < ata.fields.segment_terminal_revision).then_some(ata)
}

/// The #846 gate under an admin-armed ATA (§2): `Some(sequence)` while
/// armed. The caller requires each catch-up page to stay inside it.
pub(super) async fn armed_admin_sequence(
    state: &AppState,
    info: &GroupInfo,
) -> Option<Vec<String>> {
    armed_admin_ata(state, info)
        .await
        .map(|ata| ata.fields.sequence)
}

/// This node's live recovery tokens: the marker, an owner-armed gap
/// record, and an admin-armed ATA (§3 `Gap`).
async fn live_refs(state: &AppState, info: &GroupInfo) -> Vec<RecoveryRef> {
    let mut refs = RecoveryRef::live_refs(info);
    if let Some(ata) = armed_admin_ata(state, info).await {
        refs.push(RecoveryRef::Gap {
            reason: s3::ADMIN_ATTESTED_GAP_REASON.to_string(),
            head_state_hash: info.state_hash.clone(),
            terminal_revision: ata.fields.segment_terminal_revision,
            terminal_state_hash: ata.fields.sequence.last().cloned().unwrap_or_default(),
        });
    }
    refs
}

/// Retire the admin-armed ATA once its exact segment terminal is durably
/// applied (§2 "Retirement"), with the S3 state that went with it. A
/// marker's retirement never touches it, and it never touches a marker.
pub(super) async fn retire_converged(state: &Arc<AppState>, group_id: &str) {
    let Some(group_key) = super::resolve_named_group_storage_key(state, group_id).await else {
        return;
    };
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return;
    };
    let stable = info.stable_group_id().to_string();
    let Some(ata) = sidecar_snapshot(state, &stable)
        .await
        .and_then(|body| body.active_ata)
    else {
        return;
    };
    let terminal_hash = ata.fields.sequence.last().cloned().unwrap_or_default();
    let converged = info.state_revision >= ata.fields.segment_terminal_revision
        && info.commit_log.iter().any(|entry| {
            entry.commit.revision == ata.fields.segment_terminal_revision
                && entry.commit.state_hash == terminal_hash
        });
    if !converged {
        return;
    }
    if !update_sidecar(state, &stable, |body| {
        body.served_chain.clear();
        body.active_ata = None;
        body.queued_terminal = None;
    })
    .await
    {
        return;
    }
    state
        .group_recovery
        .inner
        .lock()
        .await
        .subjects
        .remove(&stable);
    tracing::info!(group_id = %LogHexId::group(&group_key), "ADR 0109 S3: attested catch-up reached its terminal; the armed ATA is retired");
}

async fn set_view(state: &AppState, stable_group_id: &str, revision: u64, view: SubjectView) {
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    let subject = inner
        .subjects
        .entry(stable_group_id.to_string())
        .or_insert_with(|| SubjectState::new(now, revision));
    subject.view = view;
}

// ─── §2 The subject's request loop ─────────────────────────────────────────

/// The S3 worker: loads the sidecars, resumes re-seat journals, then runs
/// the subject's request loop and the staged-join progress check. Runs
/// until shutdown.
pub(in crate::server) async fn run_group_recovery_worker(state: Arc<AppState>) {
    load_sidecars(&state).await;
    resume_journals(&state).await;
    let mut interval = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            biased;
            () = state.shutdown_started.cancelled() => break,
            _ = interval.tick() => {}
        }
        reseat_progress(&state).await;
        subject_tick(&state).await;
        prune_admin_state(&state).await;
    }
}

async fn prune_admin_state(state: &AppState) {
    let now = Instant::now();
    let now_wall = now_ms();
    let mut inner = state.group_recovery.inner.lock().await;
    for list in inner.recovery_lists.values_mut() {
        list.retain(|entry| now.saturating_duration_since(entry.at) < s3::RECOVERY_LIST_TTL);
    }
    inner.recovery_lists.retain(|_, list| !list.is_empty());
    let issued: Vec<(String, Vec<String>)> = inner
        .sidecars
        .iter()
        .filter(|(_, body)| !body.issued_reseats.is_empty())
        .map(|(group, body)| {
            (
                group.clone(),
                body.issued_reseats
                    .iter()
                    .map(|issued| issued.authorisation.fields.subject.clone())
                    .collect(),
            )
        })
        .collect();
    drop(inner);
    // §3: an authorisation is kept until consumed (its subject is Active
    // again on this roster) or expired.
    for (group, subjects) in issued {
        let seated: Vec<String> = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == group)
                .map(|info| {
                    subjects
                        .iter()
                        .filter(|subject| info.has_active_member(subject))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };
        let due = {
            let inner = state.group_recovery.inner.lock().await;
            inner.sidecars.get(&group).is_some_and(|body| {
                body.issued_reseats.iter().any(|issued| {
                    issued.authorisation.fields.expires_at_ms <= now_wall
                        || seated.contains(&issued.authorisation.fields.subject)
                })
            })
        };
        if due {
            let _ = update_sidecar(state, &group, |body| {
                body.issued_reseats.retain(|issued| {
                    issued.authorisation.fields.expires_at_ms > now_wall
                        && !seated.contains(&issued.authorisation.fields.subject)
                });
            })
            .await;
        }
    }
}

/// The groups this tick looks at: every group with a marker or an armed
/// owner gap, and every group S3 already holds state for. Only those are
/// cloned (a record can carry a long retained commit log). Also returns
/// every live group's stable ID.
async fn tick_groups(state: &AppState) -> (Vec<(String, GroupInfo)>, HashSet<String>) {
    let held: HashSet<String> = {
        let inner = state.group_recovery.inner.lock().await;
        inner
            .subjects
            .keys()
            .chain(inner.sidecars.keys())
            .chain(inner.sidecar_status.keys())
            .cloned()
            .collect()
    };
    let groups = state.named_groups.read().await;
    let mut live = HashSet::new();
    let mut selected = Vec::new();
    for (key, info) in groups.iter() {
        if info.withdrawn {
            continue;
        }
        let stable = info.stable_group_id();
        live.insert(stable.to_string());
        if held.contains(stable) || !RecoveryRef::live_refs(info).is_empty() {
            selected.push((key.clone(), info.clone()));
        }
    }
    (selected, live)
}

async fn subject_tick(state: &Arc<AppState>) {
    let local = local_hex(state);
    let (groups, live) = tick_groups(state).await;
    let now = Instant::now();
    for (key, info) in groups {
        let stable = info.stable_group_id().to_string();
        let refs = live_refs(state, &info).await;
        let (journal_active, fault) = {
            let inner = state.group_recovery.inner.lock().await;
            (
                inner
                    .sidecars
                    .get(&stable)
                    .is_some_and(|body| body.reseat_journal.is_some()),
                inner.sidecar_status.contains_key(&stable),
            )
        };
        if journal_active || fault {
            continue;
        }
        if retire_marker_attested(state, &key, &info).await {
            continue;
        }
        retire_converged(state, &key).await;
        if refs.is_empty() {
            let mut inner = state.group_recovery.inner.lock().await;
            let drop_entry = inner
                .subjects
                .get(&stable)
                .is_some_and(|subject| !matches!(subject.view, SubjectView::CatchingUp { .. }));
            if drop_entry {
                inner.subjects.remove(&stable);
            }
            continue;
        }
        if is_home_policy_group(&info) {
            set_view(
                state,
                &stable,
                info.state_revision,
                SubjectView::Deferred {
                    cause: "home_gate_closed",
                },
            )
            .await;
            continue;
        }
        let Some(target) = next_target(state, &key, &info, &local, &refs, now).await else {
            continue;
        };
        send_request(state, &info, &local, &refs, target).await;
    }
    // Refresh the cached `recovery` objects for the §5 refusal body.
    let (groups, _) = tick_groups(state).await;
    let mut cache = HashMap::new();
    for (key, info) in &groups {
        if let Some(object) = recovery_json(state, info).await {
            cache.insert(info.stable_group_id().to_string(), object.clone());
            cache.insert(key.clone(), object);
        }
    }
    let mut inner = state.group_recovery.inner.lock().await;
    inner.subjects.retain(|group, _| live.contains(group));
    inner.recovery_cache = cache;
}

/// ADR 0109 §8: the `recovery` object for the ADR 0066 §5 refusal body,
/// from the worker's last refresh (synchronous; `None` under contention or
/// when S3 holds no state for the group).
pub(in crate::server) fn cached_recovery_json(
    state: &AppState,
    group_id: &str,
) -> Option<serde_json::Value> {
    state
        .group_recovery
        .inner
        .try_lock()
        .ok()?
        .recovery_cache
        .get(group_id)
        .cloned()
}

/// §2 "Retirement": a marker, with its matching fork evidence, retires
/// (cause `attested_catchup`) once the evidenced commit
/// `(revision, state_hash, committed_by)` is durably applied under a
/// verified ATA. A sibling marker can never meet this, and the gap record
/// is untouched. Returns whether it retired one.
async fn retire_marker_attested(state: &Arc<AppState>, group_key: &str, info: &GroupInfo) -> bool {
    let Some(marker) = info.fork_quarantine.as_ref() else {
        return false;
    };
    let stable = info.stable_group_id().to_string();
    let Some(ata) = sidecar_snapshot(state, &stable)
        .await
        .and_then(|body| body.active_ata)
    else {
        return false;
    };
    let applied = info.commit_log.iter().any(|entry| {
        entry.commit.revision == marker.revision
            && entry.commit.state_hash == marker.state_hash
            && entry
                .commit
                .committed_by
                .eq_ignore_ascii_case(&marker.committed_by)
    }) && ata.fields.sequence.contains(&marker.state_hash)
        && ata.signer_verified_on(info);
    if !applied {
        return false;
    }
    let identity = RecoveryRef::from_marker(marker);
    let key = group_key.to_string();
    let outcome = super::persist_named_groups_quarantine_clear_gated(state, move |groups| {
        let Some(info) = crate::server::resolve_group_entry_mut_locked(groups, &key) else {
            return false;
        };
        let same = info
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| RecoveryRef::from_marker(marker) == identity);
        if same {
            info.fork_quarantine = None;
            info.reset_fork_evidence_after_quarantine_clear();
        }
        same
    })
    .await;
    if !matches!(outcome, Ok(super::AtomicWriteOutcome::Durable)) {
        return false;
    }
    let resumed = super::super::tasks::resume_group_task_ingest(state, &stable).await;
    tracing::info!(
        group_id = %LogHexId::group(&stable),
        resumed,
        "ADR 0109 S3: marker retired (attested_catchup): its evidenced commit applied under a verified ATA"
    );
    true
}

/// Decide whether this node asks now, and whom (§2 "Requests").
async fn next_target(
    state: &Arc<AppState>,
    _group_key: &str,
    info: &GroupInfo,
    local: &str,
    refs: &[RecoveryRef],
    now: Instant,
) -> Option<AgentId> {
    let stable = info.stable_group_id().to_string();
    let marker = info.fork_quarantine.is_some();
    let targets = ordered_targets(state, info, local);
    let mut inner = state.group_recovery.inner.lock().await;
    let subject = inner
        .subjects
        .entry(stable.clone())
        .or_insert_with(|| SubjectState::new(now, info.state_revision));
    if info.state_revision != subject.progress_revision {
        subject.progress_revision = info.state_revision;
        subject.progress_at = now;
    }
    // A gap record alone asks only after GATE_STALL without progress; an
    // armed admin ATA asks for its renewal after ATA_ARMED_LIFETIME.
    let gap_only = !marker && refs.iter().all(|r| matches!(r, RecoveryRef::Gap { .. }));
    let admin_armed = refs.iter().any(
        |r| matches!(r, RecoveryRef::Gap { reason, .. } if reason == s3::ADMIN_ATTESTED_GAP_REASON),
    );
    let stall = if admin_armed {
        s3::ATA_ARMED_LIFETIME
    } else {
        s3::GATE_STALL
    };
    if gap_only {
        if now.saturating_duration_since(subject.progress_at) < stall {
            return None;
        }
        if admin_armed && !subject.view.sticky() {
            subject.view = SubjectView::Awaiting {
                reason: "renewal_due".to_string(),
            };
        }
    }
    if let Some((_, asked_at)) = subject.pending {
        if now.saturating_duration_since(asked_at) < ANSWER_WAIT {
            return None;
        }
        // No reply from that target: try the next one in this round.
        subject.pending = None;
        subject.next_target = subject.next_target.saturating_add(1);
        if subject.next_target >= targets.len() {
            if !subject.view.sticky() {
                subject.view = SubjectView::Awaiting {
                    reason: "no_reply".to_string(),
                };
            }
            subject.end_round(now);
            return None;
        }
    }
    if now < subject.next_retry_at {
        return None;
    }
    if subject.next_target >= targets.len() && !targets.is_empty() {
        // Every target in this round refused: back off.
        subject.end_round(now);
        return None;
    }
    if targets.is_empty() {
        if !subject.view.sticky() {
            subject.view = SubjectView::Awaiting {
                reason: "no_capable_peer".to_string(),
            };
        }
        subject.end_round(now);
        return None;
    }
    let target = targets.get(subject.next_target).copied()?;
    subject.pending = Some((*target.as_bytes(), now));
    subject
        .asked
        .entry(hex::encode(target.as_bytes()))
        .or_insert_with(|| "pending".to_string());
    Some(target)
}

/// Targets in the §2 order: capable admins on this node's roster, lowest
/// agent ID first (D40); then capable members; then agents whose verified
/// commits this node holds evidence of (the marker's and the gap record's
/// committer). Only a current verified positive advert counts.
fn ordered_targets(state: &Arc<AppState>, info: &GroupInfo, local: &str) -> Vec<AgentId> {
    let mut admins = Vec::new();
    let mut members = Vec::new();
    for (id, member) in &info.members_v2 {
        if id.eq_ignore_ascii_case(local) || !member.is_active() {
            continue;
        }
        let Some(raw) = parse_raw(id) else {
            continue;
        };
        if member.role.at_least(x0x::groups::GroupRole::Admin) {
            admins.push(raw);
        } else {
            members.push(raw);
        }
    }
    admins.sort_unstable();
    members.sort_unstable();
    let mut extra = Vec::new();
    if let Some(marker) = info.fork_quarantine.as_ref() {
        extra.push(marker.committed_by.clone());
    }
    if let Some(record) = info
        .invite_lineage
        .as_ref()
        .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
    {
        extra.push(record.committed_by.clone());
    }
    let mut out: Vec<AgentId> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let extra_raw = extra
        .iter()
        .filter(|id| !id.eq_ignore_ascii_case(local))
        .filter_map(|id| parse_raw(id));
    for raw in admins.into_iter().chain(members).chain(extra_raw) {
        if !seen.insert(raw) {
            continue;
        }
        let agent = AgentId(raw);
        if peer_capable(state, &agent) == Some(true) {
            out.push(agent);
        }
    }
    out
}

async fn send_request(
    state: &Arc<AppState>,
    info: &GroupInfo,
    local: &str,
    refs: &[RecoveryRef],
    target: AgentId,
) {
    let Some(requester) = parse_raw(local) else {
        return;
    };
    let causes: Vec<(RecoveryRef, String)> = {
        let inner = state.group_recovery.inner.lock().await;
        let conflict = inner
            .subjects
            .get(info.stable_group_id())
            .is_some_and(|subject| {
                matches!(
                    subject.view,
                    SubjectView::Reseat {
                        cause: "attestation_conflict",
                        ..
                    }
                )
            });
        refs.iter()
            .map(|recovery_ref| {
                let cause = if conflict {
                    "attestation_conflict"
                } else {
                    match recovery_ref {
                        RecoveryRef::Marker { .. } => "marker",
                        RecoveryRef::Gap { .. } => "gap",
                    }
                };
                (recovery_ref.clone(), cause.to_string())
            })
            .collect()
    };
    let request = GroupAttestRequestV1 {
        group: info.stable_group_id().to_string(),
        requester,
        head_revision: info.state_revision,
        head_state_hash: info.state_hash.clone(),
        refs: causes,
    };
    let payload = match s3::encode_message(&GroupRecoveryMessageV1::Request(request)) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, "ADR 0109 S3: cannot encode a request");
            return;
        }
    };
    let task_state = Arc::clone(state);
    let group = info.stable_group_id().to_string();
    let _spawned = state.spawn_detached(async move {
        if let Err(error) = task_state.agent.send_direct(&target, payload).await {
            tracing::debug!(%error, group_id = %LogHexId::group(&group), "ADR 0109 S3: group_attest_request not sent");
        } else {
            tracing::info!(
                group_id = %LogHexId::group(&group),
                target = %LogHexId::agent(&hex::encode(target.as_bytes())),
                "ADR 0109 S3: sent group_attest_request"
            );
        }
    });
}

// ─── §2/§3 The subject's response handling ─────────────────────────────────

async fn handle_response(state: &Arc<AppState>, sender: AgentId, response: GroupAttestResponseV1) {
    let local = local_hex(state);
    if hex::encode(response.subject) != local {
        return;
    }
    let Some(group_key) = super::resolve_named_group_storage_key(state, &response.group).await
    else {
        return;
    };
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return;
    };
    let stable = info.stable_group_id().to_string();
    let sender_hex = hex::encode(sender.as_bytes());
    let answer_name = response.answer.name().to_string();
    if let AttestAnswer::Reseat {
        authorisation,
        invite,
    } = response.answer
    {
        consume_reseat(state, &group_key, *authorisation, invite).await;
        return;
    }
    // Every other answer is for this node's current head only.
    if response.for_head_state_hash != info.state_hash {
        return;
    }
    let refs = live_refs(state, &info).await;
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    let subject = inner
        .subjects
        .entry(stable.clone())
        .or_insert_with(|| SubjectState::new(now, info.state_revision));
    subject
        .asked
        .insert(sender_hex.clone(), answer_name.clone());
    let from_pending = subject
        .pending
        .is_some_and(|(target, _)| target == *sender.as_bytes());
    if from_pending {
        subject.pending = None;
    }
    match response.answer {
        AttestAnswer::NotOnChain(_) => {
            subject.view = SubjectView::Reseat {
                cause: "not_on_chain",
                recovery_ref: refs.first().cloned(),
            };
            subject.end_round(now);
        }
        AttestAnswer::OnChain(head) => {
            let sibling = info.fork_quarantine.as_ref().filter(|marker| {
                head.state_hash == info.state_hash && marker.state_hash != info.state_hash
            });
            if let Some(marker) = sibling {
                subject.view = SubjectView::ManualClear {
                    recovery_ref: RecoveryRef::from_marker(marker),
                };
            }
            subject.end_round(now);
        }
        AttestAnswer::Attested(ata) => {
            drop(inner);
            arm_from_response(state, &group_key, &info, *ata).await;
        }
        AttestAnswer::Refused(reason) => {
            subject.last_refusal = Some(reason.as_str().to_string());
            match reason {
                AttestRefusalReason::BannedOrRevoked => {
                    subject.view = SubjectView::Refused {
                        reason: "banned_or_revoked",
                    };
                    subject.end_round(now);
                }
                AttestRefusalReason::NotAMember => {
                    if !matches!(subject.view, SubjectView::ReseatInProgress { .. }) {
                        subject.view = SubjectView::Reseat {
                            cause: "not_a_member",
                            recovery_ref: refs.first().cloned(),
                        };
                    }
                    advance_round(subject, now, from_pending);
                }
                AttestRefusalReason::BaseBeyondRetention => {
                    let all_beyond = !subject.asked.is_empty()
                        && subject
                            .asked
                            .values()
                            .all(|answer| answer == "base_beyond_retention");
                    if all_beyond {
                        subject.view = SubjectView::Readmission {
                            cause: "base_beyond_retention",
                        };
                    }
                    advance_round(subject, now, from_pending);
                }
                other => {
                    if !subject.view.sticky() {
                        subject.view = SubjectView::Awaiting {
                            reason: other.as_str().to_string(),
                        };
                    }
                    advance_round(subject, now, from_pending);
                }
            }
        }
        AttestAnswer::Reseat { .. } => {}
    }
}

/// A refusal moves the round to the next target at once; the last one
/// ends the round.
fn advance_round(subject: &mut SubjectState, now: Instant, from_pending: bool) {
    if !from_pending {
        return;
    }
    // `next_target` past the list ends the round on the next tick.
    subject.next_target = subject.next_target.saturating_add(1);
    subject.next_retry_at = now;
}

/// An ATA from the request path (§2): verify it for this node, then arm
/// the gate when this node has an invite lineage to hold the record, and
/// ask the attester for the next catch-up page. Conflicting ATAs for one
/// head stop automatic catch-up.
async fn arm_from_response(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    ata: AdminTerminalAttestation,
) {
    let local = local_hex(state);
    let stable = info.stable_group_id().to_string();
    let signer_revoked = match parse_raw(&ata.fields.attested_by) {
        Some(raw) => agent_revoked(state, &AgentId(raw)).await,
        None => true,
    };
    if let Err(refusal) = ata.verify_for_subject(
        &stable,
        &local,
        info.state_revision,
        &info.state_hash,
        now_ms(),
        signer_revoked,
    ) {
        tracing::info!(group_id = %LogHexId::group(group_key), reason = refusal.as_str(), "ADR 0109 S3: ATA refused");
        return;
    }
    if let Some(active) = sidecar_snapshot(state, &stable)
        .await
        .and_then(|body| body.active_ata)
    {
        if active.conflicts_with(&ata) {
            set_view(
                state,
                &stable,
                info.state_revision,
                SubjectView::Reseat {
                    cause: "attestation_conflict",
                    recovery_ref: RecoveryRef::live_refs(info).into_iter().next(),
                },
            )
            .await;
            return;
        }
    }
    // A pre-Welcome joiner that kept its served chain applies it now.
    let pre_welcome = !info.has_active_member(&local)
        && !state.treekem_groups.read().await.contains_key(group_key);
    if pre_welcome && apply_kept_chain(state, group_key, info, &ata).await {
        return;
    }
    let verified = ata.signer_verified_on(info);
    if !verified {
        // A non-joiner verifies a provisional signer's promotion path by
        // applying those links through the ordinary path, ungated; until
        // then the ATA has no gate authority.
        set_view(
            state,
            &stable,
            info.state_revision,
            SubjectView::Awaiting {
                reason: "provisional_unverified".to_string(),
            },
        )
        .await;
        return;
    }
    // An owner-attested record keeps precedence (§2 "Arming").
    let owner_armed = info
        .invite_lineage
        .as_ref()
        .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
        .is_some_and(|record| {
            record.reason == s3::OWNER_ATTESTED_GAP_REASON
                && info.state_revision < record.terminal_revision
        });
    if owner_armed {
        return;
    }
    // The armed record lives in the sidecar only (see `apply_join_carry`).
    let ata_kept = ata.clone();
    if !update_sidecar(state, &stable, move |body| {
        body.active_ata = Some(ata_kept);
    })
    .await
    {
        return;
    }
    set_view(
        state,
        &stable,
        info.state_revision,
        SubjectView::CatchingUp {
            attested_by: ata.fields.attested_by.clone(),
            verified,
            segment_terminal: ata.fields.segment_terminal_revision,
        },
    )
    .await;
    if let Some(raw) = parse_raw(&ata.fields.attested_by) {
        let _ = super::request_treekem_catchup_page(state, group_key, &AgentId(raw)).await;
    }
}

/// §4 retention (D148): every ADR 0108 §5a copy of the group's sidecar,
/// pending or history, with its `txid` and size. Copies are never deleted
/// automatically.
async fn quarantined_copies(state: &AppState, stable_group_id: &str) -> Vec<serde_json::Value> {
    let file = s3::sidecar_file_name(stable_group_id);
    let Ok(mut entries) = tokio::fs::read_dir(sidecar_dir(state)).await else {
        return Vec::new();
    };
    let mut copies = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&format!("{file}.q-")) else {
            continue;
        };
        let (state_label, stem) = match rest.strip_suffix(".pending") {
            Some(stem) => ("pending", stem),
            None => ("history", rest),
        };
        let txid = stem.split('-').next().unwrap_or_default().to_string();
        let size = entry.metadata().await.map(|meta| meta.len()).unwrap_or(0);
        copies.push(serde_json::json!({
            "file": name,
            "txid": txid,
            "state": state_label,
            "size": size,
        }));
    }
    copies
}

// ─── §3 The admin's manual re-seat ─────────────────────────────────────────

/// `POST /groups/:id/members/:agent_id/reseat` request body.
#[derive(Debug, serde::Deserialize)]
pub(in crate::server) struct ReseatRequest {
    /// The operator's reason; must be non-empty.
    #[serde(default)]
    reason: String,
    /// The basis the admin acts on.
    #[serde(default)]
    basis: Option<serde_json::Value>,
}

fn reseat_refusal(
    code: StatusCode,
    reason: &'static str,
    detail: serde_json::Value,
) -> axum::response::Response {
    (
        code,
        Json(serde_json::json!({
            "ok": false,
            "error": reason,
            "reason": reason,
            "detail": detail,
        })),
    )
        .into_response()
}

/// ADR 0109 §3: an admin's manual re-seat of a forked or contained node.
pub(in crate::server) async fn reseat_group_member(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Path((id, agent_id)): Path<(String, String)>,
    Json(request): Json<ReseatRequest>,
) -> impl IntoResponse {
    if request.reason.trim().is_empty() {
        return reseat_refusal(
            StatusCode::BAD_REQUEST,
            "reason_required",
            serde_json::Value::Null,
        );
    }
    let Ok(subject) = crate::server::parse_agent_id_hex(&agent_id) else {
        return super::bad_request("invalid agent_id").into_response();
    };
    let subject_hex = hex::encode(subject.as_bytes());
    let Some(basis) = request.basis.as_ref().and_then(ReseatBasis::from_json) else {
        return reseat_refusal(
            StatusCode::BAD_REQUEST,
            "basis_unknown",
            serde_json::Value::Null,
        );
    };
    let membership_lock = super::group_membership_lock(&state, &id).await;
    let membership_guard = membership_lock.lock().await;
    let local = local_hex(&state);
    let (group_key, info) = {
        let groups = state.named_groups.read().await;
        if let Err(resp) =
            crate::server::group_access::admit_admin_group_route(&groups, &id, &local)
        {
            return resp.into_response();
        }
        match crate::server::resolve_group_entry_locked(&groups, &id) {
            Some((key, info)) => (key.to_string(), info.clone()),
            None => return super::not_found("group not found").into_response(),
        }
    };
    let stable = info.stable_group_id().to_string();
    if contained(&state, &info).await {
        return reseat_refusal(
            StatusCode::CONFLICT,
            "admin_contained",
            serde_json::Value::Null,
        );
    }
    if info.has_active_member(&subject_hex) {
        return reseat_refusal(
            StatusCode::CONFLICT,
            "subject_active",
            serde_json::Value::Null,
        );
    }
    if info.is_banned(&subject_hex) || agent_revoked(&state, &subject).await {
        return reseat_refusal(
            StatusCode::CONFLICT,
            "subject_banned_or_revoked",
            serde_json::Value::Null,
        );
    }
    let basis_known = match &basis {
        ReseatBasis::Removal {
            revision,
            state_hash,
        } => s3::removal_commit_on_chain(&info, &subject_hex, *revision, state_hash),
        ReseatBasis::Ref(recovery_ref) => state
            .group_recovery
            .inner
            .lock()
            .await
            .reseat_bases
            .get(&(stable.clone(), subject_hex.clone()))
            .is_some_and(|refs| refs.contains(recovery_ref)),
    };
    if !basis_known {
        return reseat_refusal(StatusCode::CONFLICT, "basis_unknown", basis.to_json());
    }
    let mut promoted = false;
    if let Some(owner) = info.policy.admission.owner_certified_user_id() {
        let owner_path =
            state.agent.identity().user_keypair().is_some_and(|kp| {
                x0x::identity::UserId::from_public_key(kp.public_key()) == *owner
            });
        if !owner_path {
            promoted = true;
            if let Err(response) = promoted_admin_checks(&state, &info, &subject_hex, &basis).await
            {
                return response;
            }
        }
    }
    let expiry_secs = s3::RESEAT_AUTHORISATION_LIFETIME.as_secs();
    let minted = if promoted {
        match mint_reseat_invite(&state, &group_key, subject, expiry_secs).await {
            Ok(minted) => minted,
            Err(reason) => {
                return reseat_refusal(
                    StatusCode::SERVICE_UNAVAILABLE,
                    reason,
                    serde_json::Value::Null,
                );
            }
        }
    } else {
        match super::mint_invite_transaction(
            &state,
            &group_key,
            expiry_secs,
            Some(subject),
            x0x::groups::InviteOrigin::Explicit,
            actor.is_durable_owner(),
        )
        .await
        {
            Ok(minted) => minted,
            Err(refusal) => return super::mint_refusal_response(&id, refusal).into_response(),
        }
    };
    let (invite, link) = minted;
    let keypair = state.agent.identity().agent_keypair();
    let expires_at_ms = invite.expires_at.saturating_mul(1000);
    let fields = ReseatAuthorisationFields {
        group: stable.clone(),
        subject: subject_hex.clone(),
        basis: basis.clone(),
        invite_secret_hash: s3::invite_secret_hash(&invite.invite_secret),
        invite_base_revision: invite.base_state_revision.unwrap_or_default(),
        invite_base_state_hash: invite.base_state_hash.clone().unwrap_or_default(),
        signer: local.clone(),
        signer_public_key: hex::encode(keypair.public_key().as_bytes()),
        reason_hash: s3::reason_hash(request.reason.trim()),
        expires_at_ms,
    };
    let authorisation = match ReseatAuthorisation::sign(fields, keypair) {
        Ok(authorisation) => authorisation,
        Err(error) => {
            return super::api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot sign the re-seat authorisation: {error}"),
            )
            .into_response();
        }
    };
    let issued = IssuedReseatV1 {
        authorisation: authorisation.clone(),
        invite: link.clone(),
        issued_at_ms: now_ms(),
    };
    let subject_for_store = subject_hex.clone();
    if !update_sidecar(&state, &stable, move |body| {
        body.issued_reseats.retain(|existing| {
            !existing
                .authorisation
                .fields
                .subject
                .eq_ignore_ascii_case(&subject_for_store)
        });
        body.issued_reseats.push(issued);
    })
    .await
    {
        return super::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the re-seat authorisation is not durable".to_string(),
        )
        .into_response();
    }
    drop(membership_guard);
    tracing::info!(
        group_id = %LogHexId::group(&group_key),
        subject = %LogHexId::agent(&subject_hex),
        "ADR 0109 S3: re-seat authorised"
    );
    // Answer the subject's pending request now: the authorisation goes in a
    // `reseat` response under the re-seat guard (§6).
    let push_state = Arc::clone(&state);
    let push_key = group_key.clone();
    let push_response = GroupAttestResponseV1 {
        group: stable.clone(),
        subject: *subject.as_bytes(),
        for_head_state_hash: String::new(),
        answer: AttestAnswer::Reseat {
            authorisation: Box::new(authorisation.clone()),
            invite: link,
        },
    };
    let _spawned = state.spawn_detached(async move {
        send_response(
            &push_state,
            &push_key,
            subject,
            Guard::Reseat,
            &push_response,
            true,
        )
        .await;
    });
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": stable,
            "subject": subject_hex,
            "basis": basis.to_json(),
            "authorisation": {
                "signer": authorisation.fields.signer,
                "expires_at_ms": authorisation.fields.expires_at_ms,
                "digest": hex::encode(authorisation.digest()),
            },
        })),
    )
        .into_response()
}

/// `GET /groups/:id/recovery`: the admin's pending requesters (§8), the
/// re-seats it issued, and this node's own `recovery` object.
pub(in crate::server) async fn get_group_recovery(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let info = {
        let groups = state.named_groups.read().await;
        crate::server::resolve_group_entry_locked(&groups, &id).map(|(_, info)| info.clone())
    };
    let Some(info) = info else {
        return super::not_found("group not found").into_response();
    };
    let stable = info.stable_group_id().to_string();
    let recovery = recovery_json(&state, &info).await;
    // The pending requesters and issued re-seats are admin state: shown
    // only while this daemon's own seat is an active admin.
    let admin = s3::signer_is_active_admin(&info, &local_hex(&state));
    let inner = state.group_recovery.inner.lock().await;
    let requesters: Vec<serde_json::Value> = inner
        .recovery_lists
        .get(&stable)
        .filter(|_| admin)
        .map(|list| {
            list.iter()
                .map(|entry| {
                    serde_json::json!({
                        "requester": entry.requester,
                        "head_revision": entry.head_revision,
                        "head_state_hash": entry.head_state_hash,
                        "refs": entry.refs.iter().map(|(r, cause)| serde_json::json!({
                            "ref": r.to_json(),
                            "cause": cause,
                        })).collect::<Vec<_>>(),
                        "answer": entry.answer,
                        "at_ms": entry.at_ms,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let issued: Vec<serde_json::Value> = inner
        .sidecars
        .get(&stable)
        .filter(|_| admin)
        .map(|body| {
            body.issued_reseats
                .iter()
                .map(|issued| {
                    serde_json::json!({
                        "subject": issued.authorisation.fields.subject,
                        "basis": issued.authorisation.fields.basis.to_json(),
                        "issued_at_ms": issued.issued_at_ms,
                        "expires_at_ms": issued.authorisation.fields.expires_at_ms,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let retired = inner
        .sidecars
        .get(&stable)
        .map_or(0, |body| body.retired.len());
    let rebuilt_from: Vec<String> = inner
        .sidecars
        .get(&stable)
        .map(|body| body.rebuilt_from.iter().map(hex::encode).collect())
        .unwrap_or_default();
    drop(inner);
    let copies = quarantined_copies(&state, &stable).await;
    // §4: a rebuilt sidecar on an admin lost its unconsumed authorisations.
    let issued_reseats_lost = admin && !rebuilt_from.is_empty();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "group_id": stable,
            "recovery": recovery,
            "requesters": requesters,
            "issued_reseats": issued,
            "issued_reseats_lost": issued_reseats_lost,
            "retired_records": retired,
            "sidecar": {
                "file": s3::sidecar_file_name(&stable),
                "rebuilt_from": rebuilt_from,
                "copies": copies,
            },
        })),
    )
        .into_response()
}

// ─── §3a The promoted-admin re-seat mandate (wiring) ───────────────────────

/// The §3a capability floor: every current roster member that may receive
/// the chain (Active seats other than this node, online or not) whose
/// current verified advert does not set `group_reseat_mandate_v1`. A member
/// without a current advert counts as legacy.
fn reseat_floor_missing(state: &AppState, info: &GroupInfo) -> Vec<String> {
    let local = local_hex(state);
    let capabilities = state.agent.capability_store();
    let mut missing: Vec<String> = info
        .members_v2
        .iter()
        .filter(|(member, seat)| seat.is_active() && !member.eq_ignore_ascii_case(&local))
        .filter(|(member, _)| {
            parse_raw(member).is_none_or(|raw| {
                capabilities.verified_registry_supports(
                    &AgentId(raw),
                    x0x::dm::CapabilityRegistry::GROUP_RESEAT_MANDATE_V1,
                ) != Some(true)
            })
        })
        .map(|(member, _)| member.clone())
        .collect();
    missing.sort();
    missing
}

/// The subject's owner certificate as this admin holds it: the bytes kept
/// on its (Removed) seat, else the discovery evidence.
async fn subject_certificate(
    state: &AppState,
    info: &GroupInfo,
    subject_hex: &str,
) -> Option<x0x::identity::AgentCertificate> {
    if let Some(cert) = info
        .members_v2
        .get(subject_hex)
        .and_then(|seat| seat.certificate.clone())
    {
        return Some(cert);
    }
    super::owner_cert_evidence_for(state, &[subject_hex])
        .await
        .cert_for(subject_hex)
        .cloned()
}

/// The first retained commit that seated `subject_hex` before `before`.
fn seating_commit_hash(info: &GroupInfo, subject_hex: &str, before: u64) -> Option<String> {
    let mut log: Vec<&RetainedCommit> = info
        .commit_log
        .iter()
        .filter(|entry| entry.commit.revision < before)
        .collect();
    log.sort_by_key(|entry| entry.commit.revision);
    let mut seated_prior = false;
    let mut found = None;
    for entry in log {
        let seated = entry
            .roster
            .get(subject_hex)
            .is_some_and(|member| member.state == x0x::groups::GroupMemberState::Active);
        if seated && !seated_prior {
            found = Some(entry.commit.state_hash.clone());
        }
        seated_prior = seated;
    }
    found
}

/// The issued re-seat whose invite secret this `MemberJoined` redeems, for
/// this subject (§3a: the issuing admin applies checks 1 and 2 again when
/// the join request arrives).
pub(super) async fn issued_reseat_for_secret(
    state: &AppState,
    stable_group_id: &str,
    subject_hex: &str,
    invite_secret: &str,
) -> Option<IssuedReseatV1> {
    let hash = s3::invite_secret_hash(invite_secret);
    current_issued_reseat(state, stable_group_id, subject_hex)
        .await
        .filter(|issued| issued.authorisation.fields.invite_secret_hash == hash)
}

/// The outcome of the §3a seal step for one `MemberJoined`.
pub(super) enum ReseatSeal {
    /// Not a promoted-admin re-seat: seal as today.
    NotReseat,
    /// A promoted-admin re-seat: embed this mandate in place of the owner
    /// mandate.
    Mandate(Box<x0x::groups::recovery::ReseatMandateV1>),
    /// A promoted-admin re-seat whose floor or bindings fail at seal: seal
    /// nothing.
    Refused(&'static str),
}

/// §3a at seal: when this `MemberJoined` redeems a promoted-admin re-seat
/// invite (an owner-axis group, no owner key here, a paired issued
/// authorisation with a `Removal` basis), re-check the floor and sign the
/// mandate over the parent and the seat-write in `next`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn reseat_mandate_for_seat(
    state: &AppState,
    parent: &GroupInfo,
    next: &GroupInfo,
    subject_hex: &str,
    invite_secret: &str,
    epoch: u64,
    certificate: Option<&x0x::identity::AgentCertificate>,
    role: x0x::groups::GroupRole,
) -> ReseatSeal {
    let Some(owner) = parent.policy.admission.owner_certified_user_id() else {
        return ReseatSeal::NotReseat;
    };
    let owner_key_here = state
        .agent
        .identity()
        .user_keypair()
        .is_some_and(|kp| x0x::identity::UserId::from_public_key(kp.public_key()) == *owner);
    if owner_key_here {
        return ReseatSeal::NotReseat;
    }
    let Some(issued) =
        issued_reseat_for_secret(state, parent.stable_group_id(), subject_hex, invite_secret).await
    else {
        return ReseatSeal::NotReseat;
    };
    let ReseatBasis::Removal {
        revision: removal_revision,
        state_hash: removal_hash,
    } = &issued.authorisation.fields.basis
    else {
        return ReseatSeal::Refused("basis_unknown");
    };
    if !reseat_floor_missing(state, parent).is_empty() {
        return ReseatSeal::Refused("reseat_receiver_upgrade_required");
    }
    let Some(certificate) = certificate else {
        return ReseatSeal::Refused("subject_certificate_unavailable");
    };
    let Some(seating) = seating_commit_hash(parent, subject_hex, *removal_revision) else {
        return ReseatSeal::Refused("basis_unknown");
    };
    let key_package_hash = next
        .members_v2
        .get(subject_hex)
        .and_then(|seat| seat.treekem_key_package_hash.clone())
        .unwrap_or_default();
    let keypair = state.agent.identity().agent_keypair();
    let fields = x0x::groups::recovery::ReseatMandateFields {
        owner_user_id: hex::encode(owner.as_bytes()),
        group_id: parent.stable_group_id().to_string(),
        genesis_hash: s3::genesis_hash(parent),
        signer: local_hex(state),
        subject: subject_hex.to_string(),
        seating_commit_hash: seating,
        removal_commit_hash: removal_hash.clone(),
        parent_commit_hash: parent.state_hash.clone(),
        terminal_roster_hash: x0x::groups::state_commit::compute_roster_root(&next.members_v2),
        invite_secret_hash: s3::invite_secret_hash(invite_secret),
        authorisation_digest: hex::encode(issued.authorisation.digest()),
        key_package_hash,
        epoch,
        certificate_digest: x0x::groups::owner_cert::certificate_digest_hex(certificate),
        policy_hash: x0x::groups::compute_policy_hash(&parent.policy),
        role,
        signer_public_key: hex::encode(keypair.public_key().as_bytes()),
    };
    match x0x::groups::recovery::ReseatMandateV1::sign(fields, keypair) {
        Ok(mandate) => ReseatSeal::Mandate(Box::new(mandate)),
        Err(_) => ReseatSeal::Refused("signature"),
    }
}

/// §3a receiver: accept a re-seat `MemberAdded` that carries a
/// `ReseatMandateV1` in place of an owner mandate, or name the failed
/// check (`reseat_mandate_invalid {cause}`). The subject itself accepts its
/// own re-seat add when the mandate binds the authorisation it consumed;
/// it holds no chain to walk (its staging record starts at the invite
/// base), and its own join validation covers the rest.
#[allow(clippy::too_many_arguments)]
pub(super) async fn verify_reseat_mandate_on_receive(
    state: &AppState,
    parent: &GroupInfo,
    next: &GroupInfo,
    commit: &GroupStateCommit,
    mandate: &x0x::groups::recovery::ReseatMandateV1,
    subject_hex: &str,
    key_package_hash: Option<&str>,
    epoch: Option<u64>,
    certificate: Option<&x0x::identity::AgentCertificate>,
) -> Result<(), &'static str> {
    let Some(owner) = parent.policy.admission.owner_certified_user_id() else {
        return Err("policy_mismatch");
    };
    if subject_hex.eq_ignore_ascii_case(&local_hex(state)) {
        let consumed = sidecar_snapshot(state, parent.stable_group_id())
            .await
            .and_then(|body| body.reseat_journal)
            .is_some_and(|journal| {
                hex::encode(journal.authorisation.digest()) == mandate.fields.authorisation_digest
                    && journal
                        .authorisation
                        .fields
                        .signer
                        .eq_ignore_ascii_case(&mandate.fields.signer)
            });
        if !consumed
            || mandate.verify_signature().is_err()
            || !commit
                .committed_by
                .eq_ignore_ascii_case(&mandate.fields.signer)
        {
            return Err("signature");
        }
        // The checks this node can make without the chain it lacks: the
        // signer's seat on its base, the exact role, and the bindings.
        if !s3::signer_is_active_admin(parent, &mandate.fields.signer) {
            return Err("signer_not_admin");
        }
        let seated_role = next.members_v2.get(subject_hex).map(|seat| seat.role);
        if seated_role != Some(mandate.fields.role) {
            return Err("role_raised");
        }
        if commit.prev_state_hash.as_deref() != Some(mandate.fields.parent_commit_hash.as_str())
            || key_package_hash.unwrap_or_default() != mandate.fields.key_package_hash
            || epoch.unwrap_or_default() != mandate.fields.epoch
            || commit.roster_root != mandate.fields.terminal_roster_hash
        {
            return Err("binding_mismatch");
        }
        return Ok(());
    }
    let subject_revoked = match parse_raw(subject_hex) {
        Some(raw) => agent_revoked(state, &AgentId(raw)).await,
        None => true,
    };
    let digest = certificate.map(x0x::groups::owner_cert::certificate_digest_hex);
    let certificate_valid = certificate.is_some_and(|cert| {
        x0x::groups::owner_cert::verify_cert_against_owner(
            owner,
            subject_hex,
            cert,
            subject_revoked,
            x0x::groups::owner_cert::restore_clock_now(),
        )
        .is_ok()
    });
    let seated_role = next
        .members_v2
        .get(subject_hex)
        .map_or(x0x::groups::GroupRole::Guest, |seat| seat.role);
    let check = x0x::groups::recovery::ReseatMandateCheck {
        parent,
        commit,
        subject: subject_hex,
        key_package_hash: Some(key_package_hash.unwrap_or_default()),
        epoch: Some(epoch.unwrap_or_default()),
        seated_role,
        certificate_digest: digest.as_deref(),
        certificate_valid,
        subject_revoked,
    };
    x0x::groups::recovery::verify_reseat_mandate(mandate, &check).map_err(|cause| cause.as_str())
}

/// §3a route checks after §3's, in order, for a promoted admin. `Ok(())`
/// means the route may mint the re-seat invite.
async fn promoted_admin_checks(
    state: &AppState,
    info: &GroupInfo,
    subject_hex: &str,
    basis: &ReseatBasis,
) -> Result<(), axum::response::Response> {
    let local = local_hex(state);
    let own_removal = match basis {
        ReseatBasis::Removal { state_hash, .. } => info.commit_log.iter().any(|entry| {
            entry.commit.state_hash == *state_hash
                && entry.commit.committed_by.eq_ignore_ascii_case(&local)
        }),
        ReseatBasis::Ref(_) => false,
    };
    if !own_removal {
        return Err(reseat_refusal(
            StatusCode::CONFLICT,
            "reseat_removal_not_own",
            serde_json::Value::Null,
        ));
    }
    let missing = reseat_floor_missing(state, info);
    if !missing.is_empty() {
        return Err(reseat_refusal(
            StatusCode::CONFLICT,
            "reseat_receiver_upgrade_required",
            serde_json::json!({ "members": missing }),
        ));
    }
    let Some(certificate) = subject_certificate(state, info, subject_hex).await else {
        return Err(reseat_refusal(
            StatusCode::CONFLICT,
            "subject_certificate_unavailable",
            serde_json::Value::Null,
        ));
    };
    let valid = info
        .policy
        .admission
        .owner_certified_user_id()
        .is_some_and(|owner| {
            x0x::groups::owner_cert::verify_cert_against_owner(
                owner,
                subject_hex,
                &certificate,
                false,
                x0x::groups::owner_cert::restore_clock_now(),
            )
            .is_ok()
        });
    if !valid {
        return Err(reseat_refusal(
            StatusCode::CONFLICT,
            "subject_certificate_invalid",
            serde_json::Value::Null,
        ));
    }
    Ok(())
}

/// Mint a re-seat invite for the promoted-admin path (§3a): an InviteV4
/// signed by this admin's agent key alone, with no owner countersignature,
/// addressed to the subject and recorded as an ordinary issued invite. Its
/// re-seat scope is the paired authorisation: only the named subject, at
/// this admin, with the matching unconsumed authorisation, can redeem it.
async fn mint_reseat_invite(
    state: &AppState,
    group_key: &str,
    subject: AgentId,
    expiry_secs: u64,
) -> Result<(x0x::groups::invite::SignedInvite, String), &'static str> {
    let info = state
        .named_groups
        .read()
        .await
        .get(group_key)
        .cloned()
        .ok_or("group_not_found")?;
    let mut invite = x0x::groups::invite::SignedInvite::new(
        info.mls_group_id.clone(),
        info.name.clone(),
        &state.agent.agent_id(),
        expiry_secs,
    );
    crate::server::routes::identity::populate_invite_base_state_v4(
        &mut invite,
        &info,
        Some(subject),
    );
    invite
        .sign_v4(state.agent.identity().agent_keypair(), None)
        .map_err(|_| "invite_sign_failed")?;
    let link = invite.encode_link().map_err(|_| "invite_too_large")?;
    let mut next = info.clone();
    next.record_issued_invite_v2(
        invite.invite_secret.clone(),
        invite.created_at,
        invite.expires_at,
        x0x::groups::GroupRole::Member,
        Some(hex::encode(subject.as_bytes())),
        x0x::groups::InviteOrigin::Explicit,
        None,
    );
    match super::persist_named_group_info(state, group_key, next).await {
        Ok(super::AtomicWriteOutcome::Durable) => Ok((invite, link)),
        _ => Err("not_durable"),
    }
}

// ─── §3 The subject's staged join and swap ─────────────────────────────────

async fn refuse_authorisation(state: &AppState, stable: &str, revision: u64, cause: &str) {
    tracing::info!(group_id = %LogHexId::group(stable), cause, "ADR 0109 S3: authorisation_refused");
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    let subject = inner
        .subjects
        .entry(stable.to_string())
        .or_insert_with(|| SubjectState::new(now, revision));
    subject.last_refusal = Some(format!("authorisation_refused:{cause}"));
    if !matches!(subject.view, SubjectView::Reseat { .. }) {
        subject.view = SubjectView::Reseat {
            cause: "reseat_failed",
            recovery_ref: None,
        };
    }
}

/// The subject's checks on an invite paired with an authorisation (§3).
fn check_reseat_invite(
    invite: &x0x::groups::invite::SignedInvite,
    authorisation: &ReseatAuthorisation,
    stable: &str,
    local: &str,
) -> Result<(), &'static str> {
    let fields = &authorisation.fields;
    if invite.stable_group_id.as_deref() != Some(stable) {
        return Err("group_mismatch");
    }
    if !invite.inviter.eq_ignore_ascii_case(&fields.signer) {
        return Err("signer_not_inviter");
    }
    if s3::invite_secret_hash(&invite.invite_secret) != fields.invite_secret_hash {
        return Err("invite_unpaired");
    }
    if invite.base_state_revision != Some(fields.invite_base_revision)
        || invite.base_state_hash.as_deref() != Some(fields.invite_base_state_hash.as_str())
    {
        return Err("invite_base_mismatch");
    }
    let Some(roster) = invite.base_roster.as_ref() else {
        return Err("invite_base_missing");
    };
    let signer_admin = roster.get(&fields.signer).is_some_and(|member| {
        member.state == x0x::groups::GroupMemberState::Active
            && member.role.at_least(x0x::groups::GroupRole::Admin)
    });
    if !signer_admin {
        return Err("signer_not_admin_on_base");
    }
    if roster
        .get(local)
        .is_some_and(|member| member.state == x0x::groups::GroupMemberState::Active)
    {
        return Err("base_seats_subject");
    }
    if invite.is_expired() {
        return Err("expired");
    }
    if invite
        .intended_joiner
        .as_deref()
        .is_some_and(|joiner| !joiner.eq_ignore_ascii_case(local))
    {
        return Err("invite_not_addressed");
    }
    Ok(())
}

/// §3: consume a verified authorisation. Journal, move the contained live
/// record aside (kept in the journal), and run an ordinary join with the
/// re-seat invite. The worker swaps on success and restores the live
/// record on failure; a crash resumes from the journal.
async fn consume_reseat(
    state: &Arc<AppState>,
    group_key: &str,
    authorisation: ReseatAuthorisation,
    invite_link: String,
) {
    let local = local_hex(state);
    let lock = super::group_membership_lock(state, group_key).await;
    let membership_guard = lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(group_key).cloned() else {
        return;
    };
    let stable = info.stable_group_id().to_string();
    if sidecar_snapshot(state, &stable)
        .await
        .is_some_and(|body| body.reseat_journal.is_some())
    {
        return;
    }
    let refs = live_refs(state, &info).await;
    if let Err(cause) = authorisation.check_for_subject(&stable, &local, &refs, now_ms()) {
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, cause).await;
        return;
    }
    let invite = match x0x::groups::invite::SignedInvite::from_link(&invite_link) {
        Ok(invite) => invite,
        Err(_) => {
            drop(membership_guard);
            refuse_authorisation(state, &stable, info.state_revision, "invite_malformed").await;
            return;
        }
    };
    if let Err(cause) = check_reseat_invite(&invite, &authorisation, &stable, &local) {
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, cause).await;
        return;
    }
    let Ok(live_record) = serde_json::to_vec(&info) else {
        return;
    };
    let live_tree = {
        let tree = state.treekem_groups.read().await.get(group_key).cloned();
        match tree {
            Some(tree) => tree.lock().await.to_snapshot_bytes().ok(),
            None => None,
        }
    };
    let journal = ReseatJournalV1 {
        authorisation: authorisation.clone(),
        invite: invite_link.clone(),
        record_digest: *blake3::hash(&live_record).as_bytes(),
        phase: ReseatPhase::Staging,
        live_key: group_key.to_string(),
        live_record,
        live_tree,
        started_at_ms: now_ms(),
    };
    if !update_sidecar(state, &stable, move |body| {
        body.reseat_journal = Some(journal);
    })
    .await
    {
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, "journal_not_durable").await;
        return;
    }
    state
        .group_recovery
        .inner
        .lock()
        .await
        .staging_live
        .insert(stable.clone());
    if !move_live_record_aside(state, group_key, &info).await {
        state
            .group_recovery
            .inner
            .lock()
            .await
            .staging_live
            .remove(&stable);
        let _ = update_sidecar(state, &stable, |body| body.reseat_journal = None).await;
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, "live_record_not_moved").await;
        return;
    }
    drop(membership_guard);
    set_view(
        state,
        &stable,
        info.state_revision,
        SubjectView::ReseatInProgress {
            authorised_by: authorisation.fields.signer.clone(),
            phase: ReseatPhase::Staging,
            expires_at_ms: authorisation.fields.expires_at_ms,
        },
    )
    .await;
    tracing::info!(
        group_id = %LogHexId::group(group_key),
        authorised_by = %LogHexId::agent(&authorisation.fields.signer),
        "ADR 0109 S3: consuming a re-seat authorisation; staged join starts"
    );
    // §3a checks 3 and 4: the owner pin comes from this node's own live
    // record (the trust root: it was admitted under that owner before), so
    // an owner-axis staged join runs in ADR 0059 §2's Home mode pinned to
    // it; the join's mode matrix then refuses `owner_mismatch` and
    // `invite_downgraded`.
    let owner_pin = info
        .policy
        .admission
        .owner_certified_user_id()
        .map(|owner| hex::encode(owner.as_bytes()));
    let request = super::JoinGroupRequest {
        invite: invite_link,
        display_name: info
            .members_v2
            .get(&local)
            .and_then(|member| member.display_name.clone()),
        mode: owner_pin.as_ref().map(|_| "home".to_string()),
        expected_owner_user_id: owner_pin,
    };
    let response = super::join_group_via_invite_inner(Arc::clone(state), request, true)
        .await
        .into_response();
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!(group_id = %LogHexId::group(group_key), %status, "ADR 0109 S3: the staged join was refused; restoring the live record");
        restore_live_record(state, &stable, &format!("join_{}", status.as_u16())).await;
    } else {
        // The join can return with the record already Active with keys:
        // swap now rather than at the next worker tick.
        swap_now_if_seated(state, &stable).await;
    }
}

/// Move the contained live record aside: the same teardown a self-removal
/// runs, so the staged join starts from no local record. The record and its
/// tree are already durable in the journal.
async fn move_live_record_aside(state: &Arc<AppState>, group_key: &str, info: &GroupInfo) -> bool {
    let aliases = super::join_artifact_group_aliases(state, group_key).await;
    super::retire_local_group_join_artifacts(state, &aliases).await;
    state.group_card_cache.write().await.remove(group_key);
    state.mls_groups.write().await.remove(group_key);
    state.treekem_groups.write().await.remove(group_key);
    super::remove_treekem_persistence_for_group_id(state, group_key, "adr0109_reseat").await;
    let key = group_key.to_string();
    let durable = matches!(
        super::persist_named_groups_mutation(state, move |groups| groups.remove(&key).is_some())
            .await,
        Ok(super::AtomicWriteOutcome::Durable)
    );
    if durable {
        super::save_mls_groups(state).await;
        let mut cache_aliases = aliases;
        cache_aliases.insert(group_key.to_string());
        cache_aliases.insert(info.stable_group_id().to_string());
        let _ = super::prune_treekem_cache_groups(state, &cache_aliases, "adr0109_reseat").await;
    }
    durable
}

/// Restore the journalled live record and close the journal; the node
/// shows `reseat_required {reseat_failed}` (§3 step 4).
async fn restore_live_record(state: &Arc<AppState>, stable: &str, why: &str) {
    let Some(journal) = sidecar_snapshot(state, stable)
        .await
        .and_then(|body| body.reseat_journal)
    else {
        return;
    };
    let Ok(record) = serde_json::from_slice::<GroupInfo>(&journal.live_record) else {
        tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the journalled live record does not decode");
        return;
    };
    let key = journal.live_key.clone();
    let lock = super::group_membership_lock(state, &key).await;
    let _membership_guard = lock.lock().await;
    // Any staging stub under the same key goes first.
    let stub_key = key.clone();
    let _ = super::persist_named_groups_mutation(state, move |groups| {
        groups.remove(&stub_key).is_some()
    })
    .await;
    state.treekem_groups.write().await.remove(&key);
    let restored = match journal.live_tree.as_deref() {
        Some(snapshot) => {
            match super::restore_local_treekem_group_from_snapshot(state, &record, snapshot) {
                Ok(tree) => {
                    let persisted = super::persist_treekem_and_named_groups_atomic_with_info(
                        state,
                        &key,
                        record.clone(),
                        &tree,
                    )
                    .await
                    .is_ok();
                    if persisted {
                        state
                            .treekem_groups
                            .write()
                            .await
                            .insert(key.clone(), Arc::new(tokio::sync::Mutex::new(tree)));
                    }
                    persisted
                }
                Err(error) => {
                    tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: cannot restore the journalled tree: {error}");
                    false
                }
            }
        }
        None => matches!(
            super::persist_named_group_info(state, &key, record.clone()).await,
            Ok(super::AtomicWriteOutcome::Durable)
        ),
    };
    if !restored {
        // The journal stays; the next tick retries the restore.
        return;
    }
    let _ = update_sidecar(state, stable, |body| body.reseat_journal = None).await;
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    inner.staging_live.remove(stable);
    let subject = inner
        .subjects
        .entry(stable.to_string())
        .or_insert_with(|| SubjectState::new(now, record.state_revision));
    subject.view = SubjectView::Reseat {
        cause: "reseat_failed",
        recovery_ref: RecoveryRef::live_refs(&record).into_iter().next(),
    };
    subject.last_refusal = Some(why.to_string());
    tracing::warn!(group_id = %LogHexId::group(stable), why, "ADR 0109 S3: re-seat failed; the contained live record is restored");
}

/// The live record whose stable id is `stable`, with its map key.
async fn live_record_for(state: &AppState, stable: &str) -> Option<(String, GroupInfo)> {
    let groups = state.named_groups.read().await;
    groups
        .iter()
        .find(|(_, info)| info.stable_group_id() == stable)
        .map(|(key, info)| (key.clone(), info.clone()))
}

/// §3 step 3: when the staged record is Active with keys, swap it in. The
/// journal closes and the old record is retired (cause `reseat`) in one
/// sidecar write, and the subject's `reseat_in_progress` view is cleared
/// with it. Returns whether the record is seated (the swap is done, by
/// this call or an earlier one, or its durable write failed and the next
/// tick retries).
///
/// The worker tick calls this, and so do the staged join's return and the
/// `recovery` object read, so a reader never sees `reseat_in_progress`
/// for a record that is already Active. The closure re-checks the journal
/// under the sidecar writer lock, so two concurrent callers retire the
/// old record once.
async fn swap_if_seated(
    state: &AppState,
    stable: &str,
    live: Option<&(String, GroupInfo)>,
    journal: &ReseatJournalV1,
) -> bool {
    let local = local_hex(state);
    let seated = match live {
        Some((key, info)) => {
            info.has_active_member(&local)
                && (info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem
                    || state.treekem_groups.read().await.contains_key(key))
        }
        None => false,
    };
    if !seated {
        return false;
    }
    let retired = RetiredRecordV1 {
        cause: "reseat".to_string(),
        retired_at_ms: now_ms(),
        record: journal.live_record.clone(),
    };
    let mut swapped = false;
    let swapped_ref = &mut swapped;
    if update_sidecar(state, stable, move |body| {
        if body.reseat_journal.take().is_some() {
            body.retire(retired);
            *swapped_ref = true;
        }
    })
    .await
    {
        let mut inner = state.group_recovery.inner.lock().await;
        inner.subjects.remove(stable);
        inner.staging_live.remove(stable);
        drop(inner);
        if swapped {
            tracing::info!(group_id = %LogHexId::group(stable), "ADR 0109 S3: re-seat swapped in; the old record is retired");
        }
    }
    true
}

/// Swap in the staged record of `stable` now if it is seated. A no-op when
/// no re-seat journal is open.
async fn swap_now_if_seated(state: &AppState, stable: &str) {
    let Some(journal) = sidecar_snapshot(state, stable)
        .await
        .and_then(|body| body.reseat_journal)
    else {
        return;
    };
    let live = live_record_for(state, stable).await;
    let _ = swap_if_seated(state, stable, live.as_ref(), &journal).await;
}

/// Swap or fail each staged join (§3 steps 3 and 4).
async fn reseat_progress(state: &Arc<AppState>) {
    let journals: Vec<(String, ReseatJournalV1)> = state
        .group_recovery
        .inner
        .lock()
        .await
        .sidecars
        .iter()
        .filter_map(|(group, body)| body.reseat_journal.clone().map(|j| (group.clone(), j)))
        .collect();
    for (stable, journal) in journals {
        let live = live_record_for(state, &stable).await;
        if swap_if_seated(state, &stable, live.as_ref(), &journal).await {
            continue;
        }
        let failed_outcome = {
            let outcomes = state
                .last_join_outcomes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let record_key = serde_json::from_slice::<GroupInfo>(&journal.live_record)
                .ok()
                .map(|record| record.mls_group_id);
            [
                Some(stable.clone()),
                Some(journal.live_key.clone()),
                record_key,
            ]
            .into_iter()
            .flatten()
            .filter_map(|key| outcomes.get(&key).cloned())
            .any(|outcome| outcome.finished_at_ms >= journal.started_at_ms)
        };
        let deadline = journal
            .authorisation
            .fields
            .expires_at_ms
            .saturating_add(u64::try_from(STAGING_GRACE.as_millis()).unwrap_or(u64::MAX));
        if failed_outcome || now_ms() > deadline {
            restore_live_record(state, &stable, "staged_join_ended").await;
        } else if live.is_none()
            && !state
                .group_recovery
                .inner
                .lock()
                .await
                .staging_live
                .contains(&stable)
        {
            // The stub is gone with no outcome and no staged join runs in
            // this process (a restart lost the in-memory stub): restore.
            restore_live_record(state, &stable, "staged_join_lost").await;
        }
    }
}

/// At start: a journal whose live record is already swapped in finalises;
/// otherwise the staged join was in memory only, so the live record is
/// restored (§3 "A crash resumes from the journal's phase").
async fn resume_journals(state: &Arc<AppState>) {
    reseat_progress(state).await;
}

// ─── §8 The recovery object ────────────────────────────────────────────────

fn ref_json(recovery_ref: Option<&RecoveryRef>) -> serde_json::Value {
    recovery_ref.map_or(serde_json::Value::Null, RecoveryRef::to_json)
}

/// The additive `recovery` object of `GET /groups/:id` (§8). `None` when
/// this node holds no S3 state for the group.
pub(in crate::server) async fn recovery_json(
    state: &AppState,
    info: &GroupInfo,
) -> Option<serde_json::Value> {
    let stable = info.stable_group_id();
    // §3 step 3: a staged record that is already Active swaps in before
    // the object is read, so `reseat_in_progress` never outlives the swap
    // by a worker tick.
    swap_now_if_seated(state, stable).await;
    let refs = live_refs(state, info).await;
    let inner = state.group_recovery.inner.lock().await;
    if let Some(fault) = inner.sidecar_status.get(stable) {
        return Some(match fault {
            SidecarFault::Unavailable { file, cause } => serde_json::json!({
                "state": "sidecar_unavailable", "file": file, "cause": cause,
            }),
            SidecarFault::NewerFormat { file, version } => serde_json::json!({
                "state": "sidecar_newer_format", "file": file,
                "version": (*version as char).to_string(),
            }),
            SidecarFault::QuarantineFailed { file, step } => serde_json::json!({
                "state": "sidecar_quarantine_failed", "file": file, "step": step,
            }),
        });
    }
    let subject = inner.subjects.get(stable);
    let rebuilt = inner
        .sidecars
        .get(stable)
        .filter(|body| !body.rebuilt_from.is_empty())
        .map(|body| {
            serde_json::json!({
                "file": s3::sidecar_file_name(stable),
                "txid": body.rebuilt_from.last().map(hex::encode),
                "lost": ["active_ata", "served_chain", "queued_terminal", "issued_reseats", "retired"],
            })
        });
    let mut object = match subject {
        None if refs.is_empty() => return None,
        None => serde_json::json!({
            "state": "awaiting_attestation",
            "reason": "no_reply",
            "asked": [],
            "next_retry_at_ms": serde_json::Value::Null,
        }),
        Some(subject) => {
            let asked: Vec<serde_json::Value> = subject
                .asked
                .iter()
                .map(|(agent, answer)| serde_json::json!({"agent": agent, "answer": answer}))
                .collect();
            let now = Instant::now();
            let next_retry_at_ms = now_ms().saturating_add(
                u64::try_from(
                    subject
                        .next_retry_at
                        .saturating_duration_since(now)
                        .as_millis(),
                )
                .unwrap_or(u64::MAX),
            );
            match &subject.view {
                SubjectView::CatchingUp {
                    attested_by,
                    verified,
                    segment_terminal,
                } => serde_json::json!({
                    "state": "catching_up",
                    "attested_by": attested_by,
                    "verified": verified,
                    "cursor": info.state_revision,
                    "segment_terminal": segment_terminal,
                }),
                SubjectView::Awaiting { reason } => serde_json::json!({
                    "state": "awaiting_attestation",
                    "reason": reason,
                    "asked": asked,
                    "next_retry_at_ms": next_retry_at_ms,
                }),
                SubjectView::Readmission { cause } => serde_json::json!({
                    "state": "readmission_required",
                    "cause": cause,
                    "asked": asked,
                    "exit": "manual_remove_and_reinvite",
                }),
                SubjectView::ManualClear { recovery_ref } => serde_json::json!({
                    "state": "manual_clear_required",
                    "ref": recovery_ref.to_json(),
                }),
                SubjectView::Reseat {
                    cause,
                    recovery_ref,
                } => serde_json::json!({
                    "state": "reseat_required",
                    "cause": cause,
                    "ref": ref_json(recovery_ref.as_ref().or(refs.first())),
                    "last_refusal": subject.last_refusal,
                    "asked": asked,
                }),
                SubjectView::ReseatInProgress {
                    authorised_by,
                    phase,
                    expires_at_ms,
                } => serde_json::json!({
                    "state": "reseat_in_progress",
                    "authorised_by": authorised_by,
                    "phase": phase.as_str(),
                    "expires_at_ms": expires_at_ms,
                }),
                SubjectView::Deferred { cause } => serde_json::json!({
                    "state": "recovery_deferred",
                    "cause": cause,
                }),
                SubjectView::Refused { reason } => serde_json::json!({
                    "state": "recovery_refused",
                    "reason": reason,
                }),
            }
        }
    };
    if let (Some(rebuilt), Some(map)) = (rebuilt, object.as_object_mut()) {
        map.insert("recovery_sidecar_rebuilt".to_string(), rebuilt);
    }
    Some(object)
}

/// The join state a held attempt reports when the 120 s poll ends (§2
/// "Join attempt (D64)"): the `recovery` state that mirrors it, or `None`
/// when S3 does not hold the attempt.
pub(in crate::server) async fn held_join_state(
    state: &AppState,
    info: &GroupInfo,
) -> Option<&'static str> {
    let armed = armed_admin_ata(state, info).await.is_some();
    let inner = state.group_recovery.inner.lock().await;
    let kept_chain = inner
        .sidecars
        .get(info.stable_group_id())
        .is_some_and(|body| !body.served_chain.is_empty());
    if !(armed || (info.fork_quarantine.is_some() && kept_chain)) {
        return None;
    }
    Some(
        match inner.subjects.get(info.stable_group_id()).map(|s| &s.view) {
            Some(SubjectView::CatchingUp { .. }) => "catching_up",
            Some(SubjectView::Readmission { .. }) => "readmission_required",
            Some(SubjectView::Reseat { .. } | SubjectView::ReseatInProgress { .. }) => {
                "reseat_required"
            }
            Some(SubjectView::Deferred { .. }) => "recovery_deferred",
            _ => "awaiting_attestation",
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responder_budget_limits_each_requester_and_builds() {
        let now = Instant::now();
        let mut budget = ResponderBudget::default();
        assert!(budget.admit([1; 32], now));
        assert!(!budget.admit([1; 32], now), "one response per interval");
        for id in 2..=4u8 {
            assert!(budget.admit([id; 32], now));
        }
        assert!(!budget.admit([9; 32], now), "four concurrent builds");
        budget.finish(10);
        assert!(budget.admit([9; 32], now));
        for _ in 0..s3::RESPONDER_SIGNATURES_PER_MINUTE {
            assert!(budget.may_sign());
        }
        assert!(!budget.may_sign());
        let later = now + Duration::from_secs(61);
        budget.roll(later);
        assert!(budget.may_sign());
        assert!(budget.per_requester.is_empty());
    }

    #[test]
    fn sticky_states_hold_against_refusals() {
        assert!(SubjectView::Reseat {
            cause: "not_on_chain",
            recovery_ref: None
        }
        .sticky());
        assert!(!SubjectView::Awaiting {
            reason: "no_reply".to_string()
        }
        .sticky());
        assert!(!SubjectView::CatchingUp {
            attested_by: String::new(),
            verified: true,
            segment_terminal: 1
        }
        .sticky());
    }

    #[test]
    fn seating_commit_is_the_first_seat_before_the_removal() {
        let admin = x0x::identity::AgentKeypair::generate().expect("keypair");
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let subject = "ab".repeat(32);
        let mut info = GroupInfo::new(
            "g".to_string(),
            String::new(),
            admin.agent_id(),
            "ef".repeat(32),
        );
        info.seal_commit(&admin, 1_000).expect("genesis seal");
        info.add_member(
            subject.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.seal_commit(&admin, 2_000).expect("seat");
        let seated = info.state_hash.clone();
        info.name = "renamed".to_string();
        info.seal_commit(&admin, 3_000).expect("rename");
        info.remove_member(&subject, Some(admin_hex));
        info.seal_commit(&admin, 4_000).expect("removal");
        let removal = info.state_revision;
        assert_eq!(seating_commit_hash(&info, &subject, removal), Some(seated));
        assert_eq!(seating_commit_hash(&info, &"cd".repeat(32), removal), None);
    }

    #[test]
    fn round_ends_with_the_section_11_backoff() {
        let now = Instant::now();
        let mut subject = SubjectState::new(now, 3);
        subject.end_round(now);
        assert_eq!(subject.attempts, 1);
        assert_eq!(subject.next_retry_at, now + Duration::from_secs(60));
        subject.end_round(now);
        assert_eq!(subject.next_retry_at, now + Duration::from_secs(120));
    }

    #[test]
    fn reseat_invite_checks_pair_the_invite_with_the_authorisation() {
        let admin = x0x::identity::AgentKeypair::generate().expect("keypair");
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let subject_hex = "ab".repeat(32);
        let mut invite = x0x::groups::invite::SignedInvite::new(
            "mls".to_string(),
            "g".to_string(),
            &admin.agent_id(),
            3600,
        );
        invite.stable_group_id = Some("stable".to_string());
        invite.base_state_revision = Some(4);
        invite.base_state_hash = Some("h4".to_string());
        invite.intended_joiner = Some(subject_hex.clone());
        let mut roster = BTreeMap::new();
        roster.insert(
            admin_hex.clone(),
            x0x::groups::state_commit::RosterMemberSnapshot {
                role: x0x::groups::GroupRole::Admin,
                state: x0x::groups::GroupMemberState::Active,
                treekem_key_package_hash: None,
                certificate_digest: None,
            },
        );
        invite.base_roster = Some(roster);
        let authorisation = ReseatAuthorisation::sign(
            ReseatAuthorisationFields {
                group: "stable".to_string(),
                subject: subject_hex.clone(),
                basis: ReseatBasis::Removal {
                    revision: 4,
                    state_hash: "h4".to_string(),
                },
                invite_secret_hash: s3::invite_secret_hash(&invite.invite_secret),
                invite_base_revision: 4,
                invite_base_state_hash: "h4".to_string(),
                signer: admin_hex.clone(),
                signer_public_key: hex::encode(admin.public_key().as_bytes()),
                reason_hash: s3::reason_hash("r"),
                expires_at_ms: u64::MAX,
            },
            &admin,
        )
        .expect("sign");
        assert_eq!(
            check_reseat_invite(&invite, &authorisation, "stable", &subject_hex),
            Ok(())
        );
        assert_eq!(
            check_reseat_invite(&invite, &authorisation, "other", &subject_hex),
            Err("group_mismatch")
        );
        assert_eq!(
            check_reseat_invite(&invite, &authorisation, "stable", &"cd".repeat(32)),
            Err("invite_not_addressed")
        );
        let mut unpaired = invite.clone();
        unpaired.invite_secret = "00".repeat(32);
        assert_eq!(
            check_reseat_invite(&unpaired, &authorisation, "stable", &subject_hex),
            Err("invite_unpaired")
        );
        let mut seated = invite.clone();
        if let Some(roster) = seated.base_roster.as_mut() {
            roster.insert(
                subject_hex.clone(),
                x0x::groups::state_commit::RosterMemberSnapshot {
                    role: x0x::groups::GroupRole::Member,
                    state: x0x::groups::GroupMemberState::Active,
                    treekem_key_package_hash: None,
                    certificate_digest: None,
                },
            );
        }
        assert_eq!(
            check_reseat_invite(&seated, &authorisation, "stable", &subject_hex),
            Err("base_seats_subject")
        );
    }
    /// The coverage marker for `POST /groups/:id/members/:agent_id/reseat`
    /// and `GET /groups/:id/recovery`: both through the REAL router and auth
    /// middleware, with the §3 route checks in order.
    #[tokio::test]
    async fn reseat_and_recovery_routes_through_real_middleware() -> anyhow::Result<()> {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let keypair = state.agent.identity().agent_keypair();
        let local = local_hex(&state);
        let subject = "ab".repeat(32);
        let bystander = "cd".repeat(32);
        let mut info = GroupInfo::with_policy(
            "adr0109-reseat".to_string(),
            "re-seat route fixture".to_string(),
            state.agent.agent_id(),
            "1109".repeat(16),
            x0x::groups::GroupPolicy {
                discoverability: x0x::groups::GroupDiscoverability::Hidden,
                admission: x0x::groups::GroupAdmission::InviteOnly,
                confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
                ..x0x::groups::GroupPolicy::default()
            },
        );
        for member in [&subject, &bystander] {
            info.add_member(
                member.clone(),
                x0x::groups::GroupRole::Member,
                Some(local.clone()),
                None,
            );
        }
        info.seal_commit(keypair, 1_000)?;
        info.remove_member(&subject, Some(local.clone()));
        info.seal_commit(keypair, 2_000)?;
        let removal_revision = info.state_revision;
        let removal_hash = info.state_hash.clone();
        let key = info.mls_group_id.clone();
        state.named_groups.write().await.insert(key.clone(), info);

        let app = axum::Router::new()
            .route(
                "/groups/:id/members/:agent_id/reseat",
                axum::routing::post(reseat_group_member),
            )
            .route(
                "/groups/:id/recovery",
                axum::routing::get(get_group_recovery),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        let token = state.api_token.clone();
        let post = |agent: &str, body: serde_json::Value, auth: bool| {
            let mut request = Request::post(format!("/groups/{key}/members/{agent}/reseat"))
                .header("content-type", "application/json");
            if auth {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            request
                .body(Body::from(body.to_string()))
                .expect("body builds")
        };
        let removal = serde_json::json!({
            "kind": "removal", "revision": removal_revision, "state_hash": removal_hash,
        });

        let response = app
            .clone()
            .oneshot(post(&subject, serde_json::json!({}), false))
            .await
            .unwrap_or_else(|never| match never {});
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(post(
                &subject,
                serde_json::json!({"reason": " ", "basis": removal}),
                true,
            ))
            .await
            .unwrap_or_else(|never| match never {});
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(body["reason"], "reason_required");

        let response = app
            .clone()
            .oneshot(post(
                &bystander,
                serde_json::json!({"reason": "r", "basis": removal}),
                true,
            ))
            .await
            .unwrap_or_else(|never| match never {});
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(body["reason"], "subject_active");

        let wrong = serde_json::json!({
            "kind": "removal", "revision": removal_revision, "state_hash": "00",
        });
        let response = app
            .clone()
            .oneshot(post(
                &subject,
                serde_json::json!({"reason": "r", "basis": wrong}),
                true,
            ))
            .await
            .unwrap_or_else(|never| match never {});
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(body["reason"], "basis_unknown");

        let response = app
            .clone()
            .oneshot(post(
                &subject,
                serde_json::json!({"reason": "forked while partitioned", "basis": removal}),
                true,
            ))
            .await
            .unwrap_or_else(|never| match never {});
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(body["subject"], subject.as_str());
        assert_eq!(body["basis"]["kind"], "removal");

        let response = app
            .oneshot(
                Request::get(format!("/groups/{key}/recovery"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("body builds"),
            )
            .await
            .unwrap_or_else(|never| match never {});
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(body["issued_reseats"][0]["subject"], subject.as_str());
        assert!(body["recovery"].is_null());
        Ok(())
    }
}
