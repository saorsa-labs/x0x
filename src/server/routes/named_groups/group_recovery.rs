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

use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};
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

mod sidecar_resume;

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
    /// §4: the groups (stable ID) whose legacy views hold an S3
    /// placeholder. A plain mutex: the roster encoder reads it
    /// synchronously, and it is never held across an await.
    placeheld: std::sync::Mutex<HashMap<String, Placeheld>>,
    /// §3 step 2 (#1533 review): per group (stable ID) with an open re-seat
    /// journal that is not yet `Swapping`, the journalled original's fork
    /// marker, which the staged record holds ([`Self::hold_reseat_markers`]).
    /// A plain mutex: the roster writers read it synchronously, and it is
    /// never held across an await.
    staging: std::sync::Mutex<HashMap<String, StagingHold>>,
    /// §2 "Conflict" and §4 at start (#1533 r8): `true` once the sidecars
    /// on disk are loaded and reconciled ([`restore_containment`]). Until
    /// then the in-memory map can be empty while disk holds a conflict, so
    /// the conflict gates wait (receivers) or refuse (local seals).
    restored: tokio::sync::watch::Sender<bool>,
    /// [`restore_containment`] runs once.
    restore_started: std::sync::atomic::AtomicBool,
    /// W3-H only: this node models a release without S3 ([`Self::model_pre_s3`]).
    #[cfg(test)]
    pre_s3: std::sync::atomic::AtomicBool,
}

impl Default for S3Runtime {
    /// A runtime with nothing on disk to restore (in-process states). The
    /// daemon uses [`Self::awaiting_restore`].
    fn default() -> Self {
        Self::with_restored(true)
    }
}

impl S3Runtime {
    /// The daemon's runtime: the conflict gates hold until
    /// [`restore_containment`] has loaded the sidecars.
    pub(in crate::server) fn awaiting_restore() -> Self {
        Self::with_restored(false)
    }

    fn with_restored(restored: bool) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(S3Inner::default()),
            writer: tokio::sync::Mutex::new(()),
            placeheld: std::sync::Mutex::new(HashMap::new()),
            staging: std::sync::Mutex::new(HashMap::new()),
            restored: tokio::sync::watch::Sender::new(restored),
            restore_started: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            pre_s3: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// W3-H (ADR 0109 Validation, "A on the previous release"): from now
    /// on this node acts, for S3, as a release without S3. It drops every
    /// `X0XGRC1` frame (as a released node drops the unknown DM), carries
    /// no join ATA and sends no request. The caller also clears bits 8 and
    /// 9 from the node's advert. Nothing else changes, so a case that uses
    /// it models S3's absence only, not every difference between releases.
    #[cfg(test)]
    pub(in crate::server) fn model_pre_s3(&self) {
        self.pre_s3.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether this node runs S3: always in a release build.
    fn runs_s3(&self) -> bool {
        #[cfg(test)]
        {
            !self.pre_s3.load(std::sync::atomic::Ordering::SeqCst)
        }
        #[cfg(not(test))]
        {
            true
        }
    }

    fn is_restored(&self) -> bool {
        *self.restored.borrow()
    }

    async fn wait_restored(&self) {
        let mut restored = self.restored.subscribe();
        // The sender lives in `self`, so the channel does not close.
        let _ = restored.wait_for(|done| *done).await;
    }
}

/// The original containment of a group whose re-seat join is staged
/// (§3 step 2). The staged record in the live map holds this marker from
/// its first roster write until the swap, so every ADR 0066 gate that reads
/// the record refuses as for the original.
#[derive(Debug, Clone)]
struct StagingHold {
    /// The stable ID and the MLS group ID of the original.
    ids: [String; 2],
    marker: x0x::groups::ForkQuarantine,
}

impl StagingHold {
    fn covers(&self, info: &GroupInfo) -> bool {
        self.ids.iter().any(|id| {
            id.eq_ignore_ascii_case(info.stable_group_id())
                || id.eq_ignore_ascii_case(&info.mls_group_id)
        })
    }
}

impl S3Runtime {
    /// Follow the group's sidecar: an open re-seat journal whose original
    /// carries a fork marker holds that marker on the staged record, until
    /// the journal is `Swapping` (the swap's own roster write lifts it).
    fn refresh_staging(&self, stable: &str, body: Option<&GroupRecoveryV1>) {
        let hold = body
            .and_then(|body| body.reseat_journal.as_ref())
            .filter(|journal| journal.phase != ReseatPhase::Swapping)
            .and_then(|journal| {
                let original = serde_json::from_slice::<GroupInfo>(&journal.live_record).ok()?;
                let marker = original.fork_quarantine.clone()?;
                Some(StagingHold {
                    ids: [
                        original.stable_group_id().to_string(),
                        original.mls_group_id.clone(),
                    ],
                    marker,
                })
            });
        let mut staging = self
            .staging
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match hold {
            Some(hold) => {
                staging.insert(stable.to_string(), hold);
            }
            None => {
                staging.remove(stable);
            }
        }
    }

    /// The marker the staged re-seat record of `info`'s group holds, if a
    /// re-seat join for the group is staged.
    pub(in crate::server) fn held_reseat_marker(
        &self,
        info: &GroupInfo,
    ) -> Option<x0x::groups::ForkQuarantine> {
        let staging = self
            .staging
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        staging
            .values()
            .find(|hold| hold.covers(info))
            .map(|hold| hold.marker.clone())
    }

    /// §3 step 2 (#1533 review, the one gate): the staged join runs apart
    /// from the original's containment. While a re-seat join for a group is
    /// staged, a record of that group that has no marker gets the
    /// journalled original's marker. Every roster write applies this before
    /// the record is visible: the stub install, the ordinary and gated
    /// persists and the TreeKEM atomic persist. So the staged record (a stub,
    /// or a seated record that is not yet swapped in) never has less
    /// containment than the original, and no clear (manual, mandate,
    /// adoption, S3 retirement) lifts it before the swap. Returns whether a
    /// record changed.
    pub(in crate::server) fn hold_reseat_marker(&self, info: &mut GroupInfo) -> bool {
        if info.fork_quarantine.is_some() {
            return false;
        }
        let Some(marker) = self.held_reseat_marker(info) else {
            return false;
        };
        info.fork_quarantine = Some(marker);
        true
    }

    /// #1645: put the re-seat journal `expected` of `stable` back to
    /// `Staging` in memory only, so the covers apply again before the
    /// durable write ([`end_swap_after_rollback`]). The next sidecar write
    /// of the group writes it.
    async fn reset_phase_in_memory(&self, stable: &str, expected: [u8; 32]) {
        let _writer = self.writer.lock().await;
        let mut inner = self.inner.lock().await;
        if let Some(body) = inner.sidecars.get_mut(stable) {
            reset_journal_to_staging(body, expected);
        }
        self.refresh_staging(stable, inner.sidecars.get(stable));
    }

    /// [`Self::hold_reseat_marker`] over every record of a roster.
    pub(in crate::server) fn hold_reseat_markers(
        &self,
        roster: &mut HashMap<String, GroupInfo>,
    ) -> bool {
        let staging = self
            .staging
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut changed = false;
        if staging.is_empty() {
            return changed;
        }
        for info in roster
            .values_mut()
            .filter(|info| info.fork_quarantine.is_none())
        {
            if let Some(hold) = staging.values().find(|hold| hold.covers(info)) {
                info.fork_quarantine = Some(hold.marker.clone());
                changed = true;
            }
        }
        changed
    }
}

/// One group whose legacy views hold an S3 placeholder (§4 "Placeholder").
#[derive(Debug, Clone)]
struct Placeheld {
    /// The live map key of the authoritative record.
    key: String,
    /// The group's last committed legacy form: what the legacy views hold
    /// on disk (#1570 rc4). Every authoritative write binds `before` to
    /// it, and a held-back save writes it again. Only a Durable legacy
    /// write advances it ([`commit_legacy_write`]), never a sidecar write
    /// alone.
    committed: LegacyForm,
    /// The form that the last encode put in the legacy view, committed
    /// when that write lands. `None` when the encode kept `committed`.
    encoded: Option<LegacyForm>,
    /// BLAKE3 of the JSON of the authoritative record that is durable in
    /// the sidecar.
    durable_digest: Option<[u8; 32]>,
    /// The last roster save could not make this group's authoritative
    /// record durable, so the legacy views kept the group's last durable
    /// form (#1570). The group's transition is not published, and the
    /// worker writes again.
    authoritative_failed: bool,
    /// #1570: a hold skipped the card routes' refresh, so once the hold
    /// ends the group's card is owed a refresh and publish. Set where a
    /// hold starts — an encode whose authoritative write failed, and an
    /// un-placeholdering whose write has not landed (the worker pass's
    /// step, or a dropped arming's rollback) — and cleared by a publish
    /// of the card: the worker pass's owed-card loop, or a reseal whose
    /// own persist ended the hold ([`settle_card_debt`]).
    card_owed: bool,
    /// #1570 (Engineer ruling, 29 Oct 2026): the worker pass un-placeheld
    /// the group, so its legacy entry is the real record again, but no
    /// Durable legacy write has landed that record yet. Until one does,
    /// the group stays held back for the card routes
    /// ([`is_card_held_back`]) and its owed card survives here: the entry
    /// leaves only with a Durable write, never with the flag.
    unplacehold_pending: bool,
    /// Load reconciliation kept a placeholder that matches neither end of
    /// its binding: the live record is that placeholder, inert, and no
    /// authoritative write runs for it.
    lost: bool,
    /// The last legacy write of the placeholder was not Durable; the worker
    /// writes it again.
    legacy_pending: bool,
}

/// One record in the form that a legacy view holds it (§4).
#[derive(Debug, Clone)]
struct LegacyForm {
    record: Arc<GroupInfo>,
    /// The view holds the record's S3 placeholder, not the real record.
    placeholder: bool,
}

impl LegacyForm {
    fn real(info: &GroupInfo) -> Self {
        Self {
            record: Arc::new(info.clone()),
            placeholder: false,
        }
    }

    fn placeholder(info: &GroupInfo) -> Self {
        Self {
            record: Arc::new(info.clone()),
            placeholder: true,
        }
    }

    /// The legacy entry of this form.
    fn entry(&self) -> GroupInfo {
        if self.placeholder {
            s3_placeholder(&self.record)
        } else {
            (*self.record).clone()
        }
    }
}

/// One subject's §3 re-seat bases and the time of its last request.
struct ReseatBases {
    refs: Vec<RecoveryRef>,
    at: Instant,
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
    /// Bounded per §11: at most `RECOVERY_LIST_CAP` subjects per group,
    /// each kept for `RECOVERY_LIST_TTL` from its last request.
    reseat_bases: HashMap<(String, String), ReseatBases>,
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
    /// #1645: per key, a failed re-seat swap whose files may be mixed (the
    /// tree write failed after its commit point and the files from before
    /// it are not all back). Every other whole-roster write waits
    /// ([`refuse_roster_write_during_failed_swap`]).
    failed_swaps: HashMap<String, FailedSwap>,
    /// Test only: where a failed swap's rollback stops (#1645).
    #[cfg(test)]
    swap_rollback_stop: Option<SwapRollbackStop>,
    /// Test only (#1708): the worker's pending step parks here, after its
    /// sidecar re-read and before its reset (`reached`, then `release`).
    #[cfg(test)]
    pending_reread_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

/// Test only (#1645): a crash point in a failed swap's rollback, or a
/// Home-Suite restore that fails.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwapRollbackStop {
    /// The process stops after the snapshot restore.
    AfterSnapshot,
    /// The process stops after the Home-Suite sidecar restore.
    AfterSidecar,
    /// The Home-Suite sidecar restore fails; the rollback goes on.
    SidecarRestoreFails,
    /// The files are back, and the durable `Staging` write fails.
    PhaseWriteFails,
    /// The snapshot restore fails (an unwritable `treekem/`).
    SnapshotRestoreFails,
}

/// A sidecar fault (§4, ADR 0108 §5a): S3 makes no transition for the
/// group while one holds.
#[derive(Debug, Clone)]
enum SidecarFault {
    Unavailable {
        file: String,
        cause: String,
    },
    NewerFormat {
        file: String,
        version: u8,
    },
    QuarantineFailed {
        file: String,
        step: String,
    },
    /// A damaged file found inside an uncommitted ADR 0094 trial: it stays
    /// in place until host commit (§4 "Before host commit").
    QuarantineDeferred {
        file: String,
    },
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

    /// Admit one request from `requester` (§1 step 2). A request over the
    /// per-requester rate gets `refused {rate_limited}`. That refusal is a
    /// response too (#1533 r10, §11): it takes a build slot and its bytes
    /// count. With no slot or no byte budget left, nothing is sent.
    fn admit(&mut self, requester: [u8; 32], now: Instant) -> Admission {
        self.roll(now);
        if self.building >= s3::RESPONDER_CONCURRENT_BUILDS
            || self.bytes >= s3::RESPONDER_BYTES_PER_MINUTE
        {
            return Admission::Drop;
        }
        let admission = match self.per_requester.entry(requester) {
            Entry::Vacant(slot) => {
                slot.insert(now);
                Admission::Build
            }
            Entry::Occupied(_) => Admission::Refuse,
        };
        self.building += 1;
        admission
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

/// What [`ResponderBudget::admit`] lets one request have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Build and send the answer.
    Build,
    /// Send a `rate_limited` refusal.
    Refuse,
    /// Send nothing.
    Drop,
}

/// The subject's own recovery, per group.
#[derive(Debug, Clone)]
struct SubjectState {
    view: SubjectView,
    /// Rounds that ended with no usable answer (the backoff exponent).
    attempts: u32,
    next_retry_at: Instant,
    /// The head the last request named, and when it was sent; cleared when
    /// the round restarts from a later head.
    asked_from: Option<(String, Instant)>,
    /// The target that refused `rate_limited` in this round and was given
    /// one cooldown retry (#1726).
    cooled: Option<[u8; 32]>,
    /// The index of the next target in the current round.
    next_target: usize,
    /// The target asked last, when, and the head the request named.
    pending: Option<([u8; 32], Instant, String)>,
    /// Each target asked and its last answer.
    asked: BTreeMap<String, String>,
    last_refusal: Option<String>,
    /// The state revision when this node last made progress; the gap
    /// trigger waits [`s3::GATE_STALL`] without progress.
    progress_revision: u64,
    progress_at: Instant,
    /// §2: a provisional ATA this node (not a joiner) verifies by applying
    /// its promotion path through the ordinary path, with the head at which
    /// it last asked the signer for a catch-up page.
    provisional: Option<(AdminTerminalAttestation, u64)>,
}

impl SubjectState {
    fn new(now: Instant, revision: u64) -> Self {
        Self {
            view: SubjectView::Awaiting {
                reason: "no_reply".to_string(),
            },
            attempts: 0,
            next_retry_at: now,
            asked_from: None,
            cooled: None,
            next_target: 0,
            pending: None,
            asked: BTreeMap::new(),
            last_refusal: None,
            progress_revision: revision,
            progress_at: now,
            provisional: None,
        }
    }

    fn end_round(&mut self, now: Instant) {
        self.attempts = self.attempts.saturating_add(1);
        self.next_retry_at = now + s3::request_backoff(self.attempts.saturating_sub(1));
        self.next_target = 0;
        self.pending = None;
        self.cooled = None;
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
        || exhausted_segment(state, info).await.is_some()
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

/// The file stem of a group's sidecar (its name without the extension).
fn sidecar_stem(stable_group_id: &str) -> String {
    let file = s3::sidecar_file_name(stable_group_id);
    file.strip_suffix(&format!(".{}", s3::GROUP_RECOVERY_EXTENSION))
        .unwrap_or(&file)
        .to_string()
}

fn sidecar_path(state: &AppState, stable_group_id: &str) -> PathBuf {
    sidecar_dir(state).join(s3::sidecar_file_name(stable_group_id))
}

/// The `recovery_deferred` cause while ADR 0094's host commit is pending.
const HOST_COMMIT_PENDING: &str = "host_commit_pending";

/// §4 "Timing" (ADR 0094: no format-upgrade writes before host commit):
/// inside an uncommitted upgrade trial, a group with no sidecar on disk
/// gets none. The node keeps today's state, so it writes no placeholder
/// either, and shows `recovery_deferred {cause: host_commit_pending}`. A
/// sidecar that is already on disk was created after an earlier host
/// commit by a binary that reads it, so it is kept current. The gate is
/// S4's ([`super::revocation_eviction::host_commit_gate_open`]): no
/// journal record or `host_committed` opens it; any other record, or an
/// unreadable one, keeps it closed.
async fn sidecar_creation_deferred(state: &AppState, stable_group_id: &str) -> bool {
    !super::revocation_eviction::host_commit_gate_open(state)
        && !matches!(
            tokio::fs::try_exists(sidecar_path(state, stable_group_id)).await,
            Ok(true)
        )
}

/// Show `recovery_deferred {cause: host_commit_pending}` and return `true`
/// when [`sidecar_creation_deferred`] holds for this group.
async fn defer_for_host_commit(state: &AppState, stable_group_id: &str, revision: u64) -> bool {
    if !sidecar_creation_deferred(state, stable_group_id).await {
        return false;
    }
    set_view(
        state,
        stable_group_id,
        revision,
        SubjectView::Deferred {
            cause: HOST_COMMIT_PENDING,
        },
    )
    .await;
    true
}

/// Write one group's sidecar durably, or remove it when empty. Returns
/// whether the bytes are durable. Inside an uncommitted ADR 0094 trial it
/// creates no new sidecar ([`sidecar_creation_deferred`]).
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
    if sidecar_creation_deferred(state, stable_group_id).await {
        tracing::info!(
            group_id = %LogHexId::group(stable_group_id),
            "ADR 0109 S3: no new sidecar before ADR 0094 host commit (recovery_deferred host_commit_pending)"
        );
        return false;
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
    update_sidecar_if(state, stable_group_id, |body| {
        mutate(body);
        true
    })
    .await
        == SidecarWrite::Written
}

/// The result of [`update_sidecar_if`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidecarWrite {
    /// The change is durable and in memory.
    Written,
    /// The guard declined the change; nothing was written.
    Declined,
    /// The sidecar has a fault, a staged re-seat refused the change, or
    /// the write is not durable; memory is unchanged.
    NotDurable,
}

/// [`update_sidecar`] for a guarded transition (#1533 r11): `mutate` runs
/// on the latest sidecar under the writer lock, so it is where a
/// transition re-checks the recovery and attestation state it depends on.
/// When it returns `false` nothing is written and the result is
/// [`SidecarWrite::Declined`]. A check on an earlier snapshot is only a
/// fast path: a concurrent reply can change the state between that read
/// and the write.
async fn update_sidecar_if<F>(state: &AppState, stable_group_id: &str, mutate: F) -> SidecarWrite
where
    F: FnOnce(&mut GroupRecoveryV1) -> bool,
{
    let runtime = &state.group_recovery;
    let _writer = runtime.writer.lock().await;
    let mut candidate = {
        let inner = runtime.inner.lock().await;
        if inner.sidecar_status.contains_key(stable_group_id) {
            return SidecarWrite::NotDurable;
        }
        inner
            .sidecars
            .get(stable_group_id)
            .cloned()
            .unwrap_or_default()
    };
    let before = staging_containment(&candidate);
    if !mutate(&mut candidate) {
        return SidecarWrite::Declined;
    }
    let refused = matches!(
        (before, staging_containment(&candidate)),
        (Some(before), Some(after)) if before != after
    );
    if refused {
        tracing::warn!(group_id = %LogHexId::group(stable_group_id), "ADR 0109 S3: a re-seat is staged; the original's containment stays until the swap, so this sidecar change is refused");
        return SidecarWrite::NotDurable;
    }
    candidate.generation = candidate.generation.saturating_add(1);
    if !write_sidecar(state, stable_group_id, &candidate).await {
        return SidecarWrite::NotDurable;
    }
    let mut inner = runtime.inner.lock().await;
    if candidate.is_empty() {
        inner.sidecars.remove(stable_group_id);
    } else {
        inner
            .sidecars
            .insert(stable_group_id.to_string(), candidate);
    }
    runtime.refresh_staging(stable_group_id, inner.sidecars.get(stable_group_id));
    SidecarWrite::Written
}

/// The sidecar fields that hold the original record's S3 containment: its
/// ATA, attestation conflict, served chain, queued terminal and the
/// authoritative record behind its placeholder.
type OriginalContainment = (
    Option<AdminTerminalAttestation>,
    Option<AdminTerminalAttestation>,
    Vec<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<s3::AuthoritativeBindingV1>,
);

fn original_containment(body: &GroupRecoveryV1) -> OriginalContainment {
    (
        body.active_ata.clone(),
        body.attestation_conflict.clone(),
        body.served_chain.clone(),
        body.queued_terminal.clone(),
        body.authoritative_record.clone(),
        body.authoritative_binding.clone(),
    )
}

/// §3 step 2 (#1533 r10): while a re-seat journal is open and not yet
/// `Swapping`, the live map holds the staged join, but the S3 state in the
/// sidecar belongs to the journalled original, and the swap (or the
/// rollback, which brings the original back) is the only exit. So no S3
/// path that reads the staged record (retirement, arming, a reply, the
/// placeholder maintenance) changes it: [`update_sidecar`] refuses such a
/// change. `Some` with the frozen fields while that holds.
fn staging_containment(body: &GroupRecoveryV1) -> Option<OriginalContainment> {
    reseat_staged(body).then(|| original_containment(body))
}

/// A re-seat journal is open and not yet `Swapping`.
fn reseat_staged(body: &GroupRecoveryV1) -> bool {
    body.reseat_journal
        .as_ref()
        .is_some_and(|journal| journal.phase != ReseatPhase::Swapping)
}

/// The groups (stable ID) whose original containment is frozen for a
/// staged re-seat ([`staging_containment`]).
async fn staging_frozen_groups(state: &AppState) -> HashSet<String> {
    state
        .group_recovery
        .inner
        .lock()
        .await
        .sidecars
        .iter()
        .filter(|(_, body)| reseat_staged(body))
        .map(|(stable, _)| stable.clone())
        .collect()
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

/// Read every `.grecov` file in `dir` (§4). Open ADR 0108 §5a quarantine
/// transactions are resumed first ([`sidecar_resume`]). A damaged file is
/// moved aside by the quarantine and replaced by an empty rebuild; a
/// newer-format file stays in place and its group is memory-only. When
/// `quarantine_open` is false (inside an uncommitted ADR 0094 trial), a
/// damaged file also stays in place, as `QuarantineDeferred` (§4 "Before
/// host commit"). Returns the loaded bodies and the faults, keyed by file
/// stem.
async fn scan_sidecar_dir(
    dir: &FsPath,
    quarantine_open: bool,
) -> (
    HashMap<String, GroupRecoveryV1>,
    HashMap<String, SidecarFault>,
) {
    let mut loaded = HashMap::new();
    let mut faults = HashMap::new();
    for (file, step) in sidecar_resume::resume_pending(dir).await {
        let stem = file
            .strip_suffix(&format!(".{}", s3::GROUP_RECOVERY_EXTENSION))
            .unwrap_or(&file)
            .to_string();
        tracing::warn!(file = %file, step, "ADR 0109 S3: interrupted sidecar quarantine did not resume; memory-only");
        faults.insert(
            stem,
            SidecarFault::QuarantineFailed {
                file,
                step: step.to_string(),
            },
        );
    }
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return (loaded, faults);
    };
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
            Err(GroupRecoveryDecodeError::Damaged(cause)) if !quarantine_open => {
                tracing::warn!(file = %name, cause, "ADR 0109 S3: damaged sidecar kept in place until ADR 0094 host commit");
                faults.insert(
                    stem.to_string(),
                    SidecarFault::QuarantineDeferred { file: name.clone() },
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
    (loaded, faults)
}

/// Load every `.grecov` file at worker start (§4), under the sidecar
/// writer lock (ADR 0108 §5a writer exclusion). See [`scan_sidecar_dir`].
async fn load_sidecars(state: &AppState) {
    let dir = sidecar_dir(state);
    let quarantine_open = super::revocation_eviction::host_commit_gate_open(state);
    let (mut loaded, mut faults) = {
        let _writer = state.group_recovery.writer.lock().await;
        scan_sidecar_dir(&dir, quarantine_open).await
    };
    // Files are named by the sanitised stable ID; map them back through
    // the live groups so the in-memory key is the stable ID itself. The
    // roster is read before the S3 lock (the roster encoder takes the S3
    // lock while it holds the roster).
    let stables: Vec<String> = state
        .named_groups
        .read()
        .await
        .values()
        .map(|info| info.stable_group_id().to_string())
        .collect();
    let mut inner = state.group_recovery.inner.lock().await;
    for stable in &stables {
        let stable = stable.as_str();
        let stem = sidecar_stem(stable);
        if let Some(body) = loaded.remove(&stem) {
            inner.sidecars.insert(stable.to_string(), body);
        }
        if let Some(fault) = faults.remove(&stem) {
            inner.sidecar_status.insert(stable.to_string(), fault);
        }
    }
    // A sidecar whose group is not in the live map holds a re-seat journal
    // (an older binary moved the live record aside before its staged join;
    // since #1699 the original stays live): keep it by its file stem, which
    // is the stable ID for every well-formed ID.
    for (stem, body) in loaded {
        if body.reseat_journal.is_some() {
            inner.sidecars.insert(stem, body);
        }
    }
    for (stable, body) in &inner.sidecars {
        state.group_recovery.refresh_staging(stable, Some(body));
    }
}

/// §4 "Before host commit": a damaged sidecar found inside an ADR 0094
/// trial stayed in place. Once host commit is written, the next tick
/// quarantines and rebuilds it as the load would have (D120).
async fn resume_deferred_quarantine(state: &AppState) {
    if !super::revocation_eviction::host_commit_gate_open(state) {
        return;
    }
    let deferred: Vec<String> = {
        let inner = state.group_recovery.inner.lock().await;
        inner
            .sidecar_status
            .iter()
            .filter(|(_, fault)| matches!(fault, SidecarFault::QuarantineDeferred { .. }))
            .map(|(stable, _)| stable.clone())
            .collect()
    };
    if deferred.is_empty() {
        return;
    }
    let (mut loaded, mut faults) = {
        let _writer = state.group_recovery.writer.lock().await;
        scan_sidecar_dir(&sidecar_dir(state), true).await
    };
    let mut inner = state.group_recovery.inner.lock().await;
    for stable in deferred {
        let stem = sidecar_stem(&stable);
        inner.sidecar_status.remove(&stable);
        if let Some(body) = loaded.remove(&stem) {
            state.group_recovery.refresh_staging(&stable, Some(&body));
            inner.sidecars.insert(stable.clone(), body);
        }
        if let Some(fault) = faults.remove(&stem) {
            inner.sidecar_status.insert(stable, fault);
        }
    }
}

/// §4 "Crash reconciliation at load": a crash between the sidecar write
/// and the legacy write leaves an active ATA whose links never became
/// durable (the loaded head is still its `from`), or one that no longer
/// matches the loaded record. Drop each such ATA, durably. Containment is
/// kept: the marker and the legacy record are untouched, and the node asks
/// again from its loaded head.
///
/// §2 "Conflict": an active ATA with a recorded conflict is never dropped
/// here. The conflict's bound is the common prefix of the two ATAs
/// ([`conflict_admits_commit`]), so dropping the ATA would remove the
/// bound, not only an admitting gate. The conflict and its ATA stay until
/// a re-seat.
async fn reconcile_loaded_atas(state: &AppState) {
    let candidates: Vec<(String, AdminTerminalAttestation)> = {
        let inner = state.group_recovery.inner.lock().await;
        inner
            .sidecars
            .iter()
            .filter(|(_, body)| body.attestation_conflict.is_none())
            .filter_map(|(stable, body)| body.active_ata.clone().map(|ata| (stable.clone(), ata)))
            .collect()
    };
    for (stable, ata) in candidates {
        let live = {
            let groups = state.named_groups.read().await;
            groups
                .values()
                .find(|info| info.stable_group_id() == stable)
                .cloned()
        };
        let head = live
            .as_ref()
            .map(|info| (info.state_revision, info.state_hash.clone()));
        // §2 "Segments": after a restart the stored ATA's signature and its
        // signer's eligibility are verified again against the loaded
        // roster before it resumes at the cursor.
        let keep = live.as_ref().is_some_and(|info| {
            s3::keep_active_ata_at_load(&ata, info.state_revision, &info.state_hash)
                && ata.verify_signature().is_ok()
                && ata.signer_verified_on(info)
        });
        if keep {
            continue;
        }
        let from = ata.fields.from_revision;
        // A conflict recorded since the scan keeps the ATA.
        let mut dropped = false;
        let written = update_sidecar(state, &stable, |body| {
            if body.attestation_conflict.is_none() {
                dropped = body.active_ata.take().is_some();
            }
        })
        .await;
        if written && dropped {
            tracing::warn!(
                group_id = %LogHexId::group(&stable),
                from,
                head = ?head.as_ref().map(|(revision, _)| *revision),
                "ADR 0109 S3: load reconciliation dropped an active ATA that does not match the loaded head or no longer verifies; containment kept"
            );
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

// ─── §4 Placeholder and authoritative record ───────────────────────────────
//
// While an admin-reason gap record is armed, every legacy file a released
// binary loads holds an S3 placeholder for the group (all-Removed roster,
// no admin), and the real record is the sidecar's `authoritative_record`.
// Released binaries never read `.grecov`, so they see an inert group and
// keep the containment that the ATA represents.
//
// The transaction (§4 "Transactions") runs inside every roster save, under
// `named_groups_persistence_lock`: [`legacy_store_view`] writes the
// authoritative record and its before/after binding to the sidecar first,
// durably, and only then gives the encoder the placeholder for the legacy
// views. A save whose sidecar write is not durable fails before any legacy
// write, so nothing is published.

fn placeheld_snapshot(state: &AppState) -> HashMap<String, Placeheld> {
    state
        .group_recovery
        .placeheld
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn with_placeheld<R>(state: &AppState, f: impl FnOnce(&mut HashMap<String, Placeheld>) -> R) -> R {
    let mut placeheld = state
        .group_recovery
        .placeheld
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut placeheld)
}

/// The sidecar body of `stable` as [`ensure_placeholders`]'s opening
/// snapshot sees it: present, fault-free, and holding something that arms
/// (an active ATA or an authoritative record). `None` when the sidecar
/// arms nothing.
fn arms_snapshot<'a>(inner: &'a S3Inner, stable: &str) -> Option<&'a GroupRecoveryV1> {
    inner
        .sidecars
        .get(stable)
        .filter(|_| !inner.sidecar_status.contains_key(stable))
        .filter(|body| body.active_ata.is_some() || body.authoritative_record.is_some())
}

/// The S3 placeholder of `info` (§4 "Placeholder"): the #451
/// `legacy_safe_placeholder` (identity, chain head and containment kept),
/// with a non-empty, all-Removed roster instead of an empty one.
///
/// #1569: an OwnerCertified group keeps its whole policy, so the #451 split
/// writes this placeholder into `home-suite-groups.json` as well. A
/// released binary lets the sidecar entry win, so it loads an inert group
/// even when `named_groups.json` still holds the #451 placeholder (empty
/// roster) after a crash in the arming save.
fn s3_placeholder(info: &GroupInfo) -> GroupInfo {
    let mut placeholder = super::legacy_safe_placeholder(info);
    placeholder.members_v2 = s3::placeholder_roster(info);
    if super::is_home_suite_group_entry(info) {
        // Only Home-Suite-aware binaries read the sidecar, so the
        // OwnerCertified variant is safe there; the split still writes the
        // default policy into `named_groups.json`.
        placeholder.policy = info.policy.clone();
    }
    placeholder
}

fn record_json(info: &GroupInfo) -> std::io::Result<(Vec<u8>, [u8; 32])> {
    let bytes = serde_json::to_vec(info).map_err(std::io::Error::other)?;
    let digest = *blake3::hash(&bytes).as_bytes();
    Ok((bytes, digest))
}

/// The key of a placeheld group's record in `groups`: its registered key,
/// or else the lowest key that holds the same stable ID.
fn placeheld_key<'a>(
    groups: &'a HashMap<String, GroupInfo>,
    stable: &str,
    entry: &Placeheld,
) -> Option<&'a String> {
    if let Some((key, info)) = groups.get_key_value(&entry.key) {
        if info.stable_group_id() == stable {
            return Some(key);
        }
    }
    groups
        .iter()
        .filter(|(_, info)| info.stable_group_id() == stable)
        .map(|(key, _)| key)
        .min()
}

/// §4 "Transactions", for the roster encoder: the view of `groups` to
/// encode into the legacy files. Every save path calls it under
/// `named_groups_persistence_lock`, before any legacy write.
///
/// First file: for each placeheld group whose record is not yet the
/// durable authoritative record, the record and its before/after binding
/// are written to the sidecar, durably. Second file: the returned view has
/// every entry (each alias) of a placeheld group replaced by its S3
/// placeholder. `None` when no group is placeheld.
///
/// The placeheld set is read once, under the persistence lock, so a group
/// that stops being placeheld meanwhile is written either wholly before or
/// wholly after that change.
///
/// #1570: when one group's authoritative record cannot be made durable,
/// only that group is held back. Its legacy entry under every key stays in
/// its last committed form (`Placeheld::committed`), it is marked
/// `authoritative_failed` (no change to it is acknowledged or published:
/// [`confirm_placeheld_write`], [`change_held_back`]), and the other
/// groups are saved.
pub(super) async fn legacy_store_view(
    state: &AppState,
    groups: &HashMap<String, GroupInfo>,
) -> Option<HashMap<String, GroupInfo>> {
    let placeheld = placeheld_snapshot(state);
    let journals = open_reseat_journals(state).await;
    if placeheld.is_empty() && journals.is_empty() {
        return None;
    }
    let placeheld_ids: HashSet<String> = placeheld.keys().cloned().collect();
    // #1533 r10: a staged re-seat keeps the original's authoritative
    // record; the live record under the key is the staged join.
    let frozen = staging_frozen_groups(state).await;
    let mut view: Option<HashMap<String, GroupInfo>> = None;
    for (stable, entry) in placeheld {
        // #1570 (Engineer ruling, 29 Oct 2026): the pass un-placeheld the
        // group, so the view holds its real record — no placeholder, no
        // authoritative write (the sidecar is retired once that write is
        // Durable). Until it is, the group stays held back for the card
        // routes ([`is_card_held_back`]). A staged re-seat keeps its
        // frozen placeholder semantics.
        if entry.unplacehold_pending && !frozen.contains(&stable) {
            // #1708 review: the encode puts the group's real record in the
            // view, so a Durable write of it commits that form. Without
            // this, a re-arm before the worker's next pass keeps a
            // `committed` form older than the durable record, and a later
            // failed authoritative write rolls the legacy views back over
            // the newer record.
            let encoded = placeheld_key(groups, &stable, &entry)
                .and_then(|key| groups.get(key))
                .map(LegacyForm::real);
            record_encode_outcome(state, &stable, false, encoded);
            continue;
        }
        // A group absent from the view, lost or frozen has no
        // authoritative write in this encode, so nothing of it is held back.
        let Some(canonical) = placeheld_key(groups, &stable, &entry).cloned() else {
            record_encode_outcome(state, &stable, false, None);
            continue;
        };
        let held_back = if !entry.lost && !frozen.contains(&stable) {
            let failed = sync_authoritative(state, &stable, &entry, &canonical, groups)
                .await
                .is_err();
            // #1570 rc4: a held-back group keeps its last COMMITTED legacy
            // form, never a sidecar record whose legacy write did not land.
            let encoded = if failed {
                None
            } else {
                groups.get(&canonical).map(LegacyForm::placeholder)
            };
            record_encode_outcome(state, &stable, failed, encoded);
            failed.then(|| entry.committed.entry())
        } else {
            record_encode_outcome(state, &stable, false, None);
            None
        };
        for (key, info) in groups {
            if info.stable_group_id() == stable.as_str() {
                // #1570 review: every key of a held-back group keeps the
                // last durable form. An alias never gets a placeholder of
                // a live record that has no durable backing.
                let legacy = match &held_back {
                    Some(held) => held.clone(),
                    None => s3_placeholder(info),
                };
                view.get_or_insert_with(|| groups.clone())
                    .insert(key.clone(), legacy);
            }
        }
    }
    if let Some(overlaid) =
        reseat_overlay(view.as_ref().unwrap_or(groups), &journals, &placeheld_ids)
    {
        view = Some(overlaid);
    }
    view
}

/// The re-seat journals that are open and not yet swapping.
async fn open_reseat_journals(state: &AppState) -> Vec<ReseatJournalV1> {
    state
        .group_recovery
        .inner
        .lock()
        .await
        .sidecars
        .values()
        .filter_map(|body| body.reseat_journal.clone())
        .filter(|journal| journal.phase != ReseatPhase::Swapping)
        .collect()
}

/// #1567: the open, not yet `Swapping` re-seat journal whose original
/// record sits under `key`. While it exists, `<key>.snap` (and the
/// TreeKEM journal envelope written with it) keeps the original's tree:
/// the TreeKEM half of [`reseat_overlay`].
pub(super) async fn staging_journal_for_key(
    state: &AppState,
    key: &str,
) -> Option<ReseatJournalV1> {
    open_reseat_journals(state)
        .await
        .into_iter()
        .find(|journal| journal.live_key == key)
}

/// §3 step 2 (#1533 review): the staged join runs apart from the
/// original's containment. While a journal is open and not yet
/// `Swapping`, every legacy file keeps the journalled original record (its
/// S3 placeholder when the group is placeheld) under the journal's key,
/// with its marker and gates, whatever the live map holds: nothing, a
/// staging stub, or a staged record that is not yet swapped. So a crash at
/// any point, or a downgrade, loads the original containment. Only the
/// swap (`Swapping`, then a durable legacy write) puts the staged record
/// on disk. `None` when no journal applies.
fn reseat_overlay(
    groups: &HashMap<String, GroupInfo>,
    journals: &[ReseatJournalV1],
    placeheld: &HashSet<String>,
) -> Option<HashMap<String, GroupInfo>> {
    let mut view: Option<HashMap<String, GroupInfo>> = None;
    for journal in journals {
        if journal.phase == ReseatPhase::Swapping {
            continue;
        }
        let Ok(original) = serde_json::from_slice::<GroupInfo>(&journal.live_record) else {
            continue;
        };
        let stable = original.stable_group_id().to_string();
        let view = view.get_or_insert_with(|| groups.clone());
        view.retain(|_, info| info.stable_group_id() != stable);
        let entry = if placeheld.contains(&stable) {
            s3_placeholder(&original)
        } else {
            original
        };
        view.insert(journal.live_key.clone(), entry);
    }
    view
}

/// `info` is the journalled original record (same revision and head), not
/// a staged result. Compared by head, not by bytes: the original can come
/// back from disk after a restart (§3 step 2).
fn is_journalled_original(info: &GroupInfo, journal: &ReseatJournalV1) -> bool {
    serde_json::from_slice::<GroupInfo>(&journal.live_record).is_ok_and(|original| {
        original.state_revision == info.state_revision && original.state_hash == info.state_hash
    })
}

/// The staged join of an open `Staging`/`Swapping` journal cannot finish:
/// no staged join runs in this process (`preparing` is false), and either
/// the journal is still `Staging` (after a restart the legacy files hold
/// the original, so the staged state is gone) or the live record is
/// absent or is the original.
fn staged_join_lost(journal: &ReseatJournalV1, live: Option<&GroupInfo>, preparing: bool) -> bool {
    !preparing
        && (journal.phase == ReseatPhase::Staging
            || live.is_none_or(|info| is_journalled_original(info, journal)))
}

/// Write `groups[key]` as the sidecar's authoritative record of `stable`
/// with its binding, unless it already is the durable one.
async fn sync_authoritative(
    state: &AppState,
    stable: &str,
    entry: &Placeheld,
    key: &str,
    groups: &HashMap<String, GroupInfo>,
) -> std::io::Result<()> {
    let Some(info) = groups.get(key) else {
        return Ok(());
    };
    let (bytes, digest) = record_json(info)?;
    if entry.durable_digest == Some(digest) {
        return Ok(());
    }
    let after = s3::AuthoritativeHead::of(info);
    // #1570 rc4: `before` is the last committed legacy form, not the
    // sidecar's previous record: a sidecar write whose legacy write did not
    // land never becomes the form that load reconciliation falls back to.
    let before = s3::AuthoritativeHead::of(&entry.committed.record);
    let before_record = if entry.committed.placeholder {
        Some(record_json(&entry.committed.record)?.0)
    } else {
        None
    };
    let live_key = key.to_string();
    let written = update_sidecar(state, stable, move |body| {
        body.authoritative_binding = Some(s3::AuthoritativeBindingV1 {
            live_key,
            before,
            before_record,
            after,
        });
        body.authoritative_record = Some(bytes);
    })
    .await;
    if !written {
        // ZCode on d1be57f1: the worker retries every tick while the
        // sidecar stays unwritable. Warn once, when the group starts to be
        // held back; the retries log at debug level.
        if entry.authoritative_failed {
            tracing::debug!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the authoritative record is still not durable; the group stays held back");
        } else {
            tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the authoritative record is not durable; the group keeps its committed legacy form");
        }
        return Err(std::io::Error::other(
            "ADR 0109 §4: the S3 authoritative record is not durable",
        ));
    }
    with_placeheld(state, |placeheld| {
        if let Some(entry) = placeheld.get_mut(stable) {
            entry.key = key.to_string();
            entry.durable_digest = Some(digest);
        }
    });
    Ok(())
}

/// Record the outcome of `stable`'s authoritative write in this encode:
/// `failed` holds the group back (#1570), and `encoded` is the form the
/// view now holds for it.
fn record_encode_outcome(
    state: &AppState,
    stable: &str,
    failed: bool,
    encoded: Option<LegacyForm>,
) {
    with_placeheld(state, |placeheld| {
        if let Some(entry) = placeheld.get_mut(stable) {
            entry.authoritative_failed = failed;
            entry.legacy_pending |= failed;
            if failed {
                entry.card_owed = true;
            }
            entry.encoded = encoded;
        }
    });
}

/// #1570 rc4, for each writer of a [`legacy_store_view`] encode (the
/// checked roster save, the TreeKEM atomic writer and the withdrawn
/// repair): the legacy write of the last encode ended with `outcome`. Only a `Durable` write commits each
/// placeheld group's encoded form. After `ReplacedNotDurable` the file
/// on disk can be either form, and the caller writes memory again (for a
/// rejected clear, the record with its marker), so the committed form
/// stays: a held-back save never writes the form of a rejected change.
pub(super) fn commit_legacy_write(
    state: &AppState,
    outcome: &std::io::Result<super::AtomicWriteOutcome>,
) {
    let landed = matches!(outcome, Ok(super::AtomicWriteOutcome::Durable));
    with_placeheld(state, |placeheld| {
        for entry in placeheld.values_mut() {
            // Always clear `encoded`: it names only the last encode.
            let encoded = entry.encoded.take();
            if let Some(encoded) = encoded.filter(|_| landed) {
                entry.committed = encoded;
            }
        }
    });
}

/// #1645 and #1570 (ZCode on d1be57f1): the committed legacy form of each
/// placeheld group, read together with the roster store bytes that hold
/// it ([`super::read_roster_stores`]). A rollback that puts those bytes
/// back puts these forms back too ([`restore_committed_forms`]), so the
/// committed form always names what is on disk.
#[derive(Debug, Clone, Default)]
pub(super) struct CommittedForms(HashMap<String, LegacyForm>);

/// Read [`CommittedForms`]. Caller holds `named_groups_persistence_lock`.
pub(super) fn committed_forms(state: &AppState) -> CommittedForms {
    with_placeheld(state, |placeheld| {
        CommittedForms(
            placeheld
                .iter()
                .map(|(stable, entry)| (stable.clone(), entry.committed.clone()))
                .collect(),
        )
    })
}

/// The legacy file holds the bytes read with `forms` again (a Durable
/// restore): each placeheld group's committed form goes back to the one
/// read then. A group placeheld since then keeps its own. No encode is
/// pending after a restore, so `encoded` is cleared.
pub(super) fn restore_committed_forms(state: &AppState, forms: &CommittedForms) {
    with_placeheld(state, |placeheld| {
        for (stable, entry) in placeheld.iter_mut() {
            entry.encoded = None;
            if let Some(form) = forms.0.get(stable) {
                entry.committed = form.clone();
            }
        }
    });
}

/// #1570: a roster save can be Durable while a placeheld group's own
/// authoritative write failed (its legacy entry kept its last committed
/// form). For that group's transition the write is then not Durable:
/// `ReplacedNotDurable` when the committed form on disk is a placeholder
/// (the record stays contained and the worker writes again), `Dropped`
/// when the legacy views hold the real record (the arming is rolled
/// back). A `ReplacedNotDurable` input (see [`held_back_outcome`])
/// follows the same rule.
fn confirm_placeheld_write(state: &AppState, stable: &str, write: LegacyWrite) -> LegacyWrite {
    if write == LegacyWrite::Dropped {
        return write;
    }
    with_placeheld(state, |placeheld| match placeheld.get(stable) {
        Some(entry) if entry.authoritative_failed => {
            if entry.committed.placeholder {
                LegacyWrite::ReplacedNotDurable
            } else {
                LegacyWrite::Dropped
            }
        }
        _ => write,
    })
}

/// #1570 review, §4 "publish only when both are durable": the outcome of
/// a per-group roster save for `stable`'s group. A `Durable` roster save
/// is `ReplacedNotDurable` for a placeheld group whose authoritative write
/// failed in that save: its legacy entry kept its last durable form, so
/// its change is not durable yet. The worker writes it again. Other
/// outcomes do not change.
pub(super) fn held_back_outcome(
    state: &AppState,
    stable: &str,
    outcome: std::io::Result<super::AtomicWriteOutcome>,
) -> std::io::Result<super::AtomicWriteOutcome> {
    use super::AtomicWriteOutcome;
    match outcome {
        Ok(AtomicWriteOutcome::Durable) if is_held_back(state, stable) => {
            Ok(AtomicWriteOutcome::ReplacedNotDurable)
        }
        outcome => outcome,
    }
}

/// #1570: `stable`'s group is placeheld and its authoritative record was
/// not durable in the last legacy encode ([`legacy_store_view`]). Its
/// legacy entry kept its last durable form, so a change to it made in that
/// encode is not on disk.
pub(super) fn is_held_back(state: &AppState, stable: &str) -> bool {
    with_placeheld(state, |placeheld| {
        placeheld
            .get(stable)
            .is_some_and(|entry| entry.authoritative_failed)
    })
}

/// #1570 (Engineer ruling, 29 Oct 2026): the card routes and card
/// publishing may act only on `stable`'s committed record. Two states put
/// a group here: its authoritative write failed ([`is_held_back`]), and
/// its un-placeholdering write has not landed (the worker pass's step, or
/// a dropped arming's rollback, [`finish_arm`]) — until it lands, the
/// live record is not the known-durable form, so no card is signed or
/// published from it. Roster mutations and save outcomes use the narrower
/// [`is_held_back`] and keep their pre-#1570 behaviour for a pending
/// un-placeholdering: its view already holds the real record, so a
/// Durable save of a change to it commits that change.
pub(super) fn is_card_held_back(state: &AppState, stable: &str) -> bool {
    with_placeheld(state, |placeheld| {
        placeheld
            .get(stable)
            .is_some_and(|entry| entry.authoritative_failed || entry.unplacehold_pending)
    })
}

/// #1570, #1708 review: a publish of `stable`'s card settled the owed
/// card, so the worker pass no longer owes one. The reseal path calls
/// this: its own persist can end the hold (Engineer ruling, 29 Oct 2026
/// 19:56) and its publish then covers the debt, or the next pass would
/// publish the same card again.
pub(super) fn settle_card_debt(state: &AppState, stable: &str) {
    with_placeheld(state, |placeheld| {
        if let Some(entry) = placeheld.get_mut(stable) {
            entry.card_owed = false;
        }
    });
}

/// #1570 rc4, the one commit check for a roster mutation from `before`
/// to `after`, run after its encode ([`legacy_store_view`]) and before its
/// legacy write: some group that the mutation touches (a key added,
/// removed or changed, under either side's stable ID) is held back. Its
/// legacy entry keeps the last committed form, so the change is not on
/// disk. The caller then writes nothing, reports nothing as Durable and
/// runs no effect of the change.
pub(super) fn change_held_back(
    state: &AppState,
    before: &HashMap<String, GroupInfo>,
    after: &HashMap<String, GroupInfo>,
) -> bool {
    before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .flat_map(|key| before.get(key).into_iter().chain(after.get(key)))
        .any(|info| is_held_back(state, info.stable_group_id()))
}

fn is_placeheld(state: &AppState, stable: &str) -> bool {
    with_placeheld(state, |placeheld| placeheld.contains_key(stable))
}

/// §4 "Crash reconciliation at load", for the roster loader: replace each
/// loaded S3 placeholder with the record its sidecar binding names
/// ([`s3::choose_authoritative`]), with the stronger containment of the
/// two. Read-only: the S3 worker finishes the reconciliation at start
/// ([`ensure_placeholders`]). An unreadable sidecar replaces nothing, so
/// its placeholder stays in place, inert (§4 "Containment first").
pub(super) async fn splice_authoritative_records(
    data_dir: &FsPath,
    merged: &mut HashMap<String, GroupInfo>,
) {
    let dir = data_dir.join(s3::GROUP_RECOVERY_DIR);
    let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
        return;
    };
    let suffix = format!(".{}", s3::GROUP_RECOVERY_EXTENSION);
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let is_sidecar = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(&suffix));
        if !is_sidecar {
            continue;
        }
        let Ok(bytes) = tokio::fs::read(&path).await else {
            continue;
        };
        let Ok(body) = s3::decode_sidecar(&bytes) else {
            continue;
        };
        let (Some(record), Some(binding)) = (
            body.authoritative_record.as_ref(),
            body.authoritative_binding.as_ref(),
        ) else {
            continue;
        };
        let Ok(authoritative) = serde_json::from_slice::<GroupInfo>(record) else {
            continue;
        };
        let stable = authoritative.stable_group_id().to_string();
        let key = if merged.contains_key(&binding.live_key) {
            binding.live_key.clone()
        } else {
            match merged
                .iter()
                .filter(|(_, info)| info.stable_group_id() == stable)
                .map(|(key, _)| key.clone())
                .min()
            {
                Some(key) => key,
                None => continue,
            }
        };
        let Some(loaded) = merged.get(&key) else {
            continue;
        };
        let chosen = match s3::choose_authoritative(binding, loaded) {
            s3::AuthoritativeChoice::After => Some(authoritative),
            s3::AuthoritativeChoice::Before => binding
                .before_record
                .as_deref()
                .and_then(|bytes| serde_json::from_slice::<GroupInfo>(bytes).ok()),
            s3::AuthoritativeChoice::KeepLoaded | s3::AuthoritativeChoice::Lost => None,
        };
        let Some(mut chosen) = chosen else {
            continue;
        };
        let (marker, evidence) = super::containment_of(loaded);
        let withdrawn = loaded.withdrawn;
        super::union_containment_into(&mut chosen, marker, evidence);
        chosen.withdrawn |= withdrawn;
        merged.insert(key, chosen);
    }
}

/// The group's admin-armed state needs the placeholder: an armed admin ATA,
/// an exhausted segment (the gate stays armed), or a recorded conflict. A
/// conflict holds the gate closed past its common prefix wherever the head
/// is, off the active ATA's chain included, until a re-seat clears it
/// (#1533 rc18).
async fn needs_placeholder(state: &AppState, info: &GroupInfo, body: &GroupRecoveryV1) -> bool {
    body.attestation_conflict.is_some()
        || armed_admin_ata(state, info).await.is_some()
        || exhausted_segment(state, info).await.is_some()
}

/// Register `info`'s group as placeheld before the legacy write of an
/// arming transition. The legacy view holds `info`'s real record.
pub(super) fn begin_placehold(state: &AppState, key: &str, info: &GroupInfo) {
    let stable = info.stable_group_id().to_string();
    with_placeheld(state, |placeheld| {
        let entry = placeheld.entry(stable).or_insert_with(|| Placeheld {
            key: key.to_string(),
            committed: LegacyForm::real(info),
            encoded: None,
            durable_digest: None,
            authoritative_failed: false,
            card_owed: false,
            unplacehold_pending: false,
            lost: false,
            legacy_pending: true,
        });
        // A new arming re-claims the placeholder: an un-placeholdering
        // whose write never landed is superseded.
        entry.unplacehold_pending = false;
    });
}

/// How the legacy write of an S3 transition ended (§4 "Transactions").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyWrite {
    Durable,
    ReplacedNotDurable,
    /// `NotReplaced`, `Err`, or a changed epoch token.
    Dropped,
}

impl LegacyWrite {
    fn of(outcome: &std::io::Result<super::AtomicWriteOutcome>) -> Self {
        match outcome {
            Ok(super::AtomicWriteOutcome::Durable) => Self::Durable,
            Ok(super::AtomicWriteOutcome::ReplacedNotDurable) => Self::ReplacedNotDurable,
            // #1574 slice 3 (Engineer ruling, 30 Oct): the preflight's
            // re-save renamed the placeholder onto disk before it
            // refused, so the arming stays contained exactly as before —
            // `Dropped` would clear the sidecar's arming while the
            // placeholder survives on disk (a crash leaves an orphan
            // load reconciliation never repairs).
            Ok(super::AtomicWriteOutcome::PreflightRefusedAfterRename) => Self::ReplacedNotDurable,
            Ok(super::AtomicWriteOutcome::NotReplaced) | Err(_) => Self::Dropped,
        }
    }
}

/// End an arming transition (§4): `Durable` publishes it. On
/// `ReplacedNotDurable` the record stays contained (the placeholder is on
/// disk, the group stays placeheld) and the worker writes again. On
/// `Dropped` nothing is published and the candidate is dropped: the group
/// no longer needs the placeholder and the sidecar's arming (the ATA and
/// the authoritative record) is rolled back. #1570 (29 Oct 2026): the
/// entry stays as a pending un-placeholdering, so an owed card survives it
/// and the group stays held back for the card routes until the real
/// record's write lands; the worker pass decides whether the group still
/// needs the placeholder, and re-claims it if it does.
/// Returns whether it is published.
async fn finish_arm(
    state: &AppState,
    stable: &str,
    write: LegacyWrite,
    armed: &AdminTerminalAttestation,
) -> bool {
    match write {
        LegacyWrite::Durable => {
            with_placeheld(state, |placeheld| {
                if let Some(entry) = placeheld.get_mut(stable) {
                    entry.legacy_pending = false;
                }
            });
            true
        }
        LegacyWrite::ReplacedNotDurable => {
            tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the placeholder write is not durable; the record stays contained and the write is retried");
            false
        }
        LegacyWrite::Dropped => {
            // #1570 (Engineer ruling, 29 Oct 2026): the entry stays, so an
            // owed card survives it. It turns pending un-placeholdering at
            // once, before the rollback below: a save before the next
            // worker pass then encodes the group's real record, never a
            // placeholder whose sidecar record the rollback clears (#1708
            // review — the arming's digest still matched, so such a save
            // wrote an orphan placeholder). The next pass decides with the
            // full sidecar state: a group that still needs the placeholder
            // (a recorded conflict, another arming) is re-claimed by the
            // supersede branch; otherwise the pass un-placeholds it, keeps
            // it held back for the card routes until its write lands, and
            // publishes the owed card.
            with_placeheld(state, |placeheld| {
                if let Some(entry) = placeheld.get_mut(stable) {
                    entry.unplacehold_pending = true;
                    entry.durable_digest = None;
                    entry.legacy_pending = true;
                    entry.authoritative_failed = false;
                    entry.card_owed = true;
                }
            });
            let _ = update_sidecar(state, stable, |body| {
                // #1533 r11: a reply can record a conflict against the armed
                // ATA, or replace it, while the legacy write runs. Only this
                // arming's ATA is withdrawn, and never under a conflict: the
                // conflict keeps its ATA, or its bound is lost.
                if body.attestation_conflict.is_none() && body.active_ata.as_ref() == Some(armed) {
                    body.active_ata = None;
                }
                body.authoritative_record = None;
                body.authoritative_binding = None;
            })
            .await;
            tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the arming transition was not written; nothing is published");
            false
        }
    }
}

/// ADR 0109 §4 "S3 publishes to the live map only when both writes are
/// Durable" (#1533 r9). The shared persist helper also installs its
/// record on `ReplacedNotDurable` (the #759 rule), so an S3 transition
/// that advances the record puts `before` back in the live map. The
/// candidate stays only in the sidecar's durable authoritative record,
/// and the group stays placeheld, so the worker writes again. A live
/// record that is no longer `after` is not changed.
async fn unpublish_not_durable(state: &AppState, key: &str, before: &GroupInfo, after: &GroupInfo) {
    {
        let _persistence_guard = state.named_groups_persistence_lock.lock().await;
        let mut groups = state.named_groups.write().await;
        let Some(live) = groups
            .get_mut(key)
            .filter(|live| live.state_hash == after.state_hash)
        else {
            return;
        };
        *live = before.clone();
    }
    super::refresh_group_rosters_for_gossip(state).await;
}

/// The live record under `key` still has the epoch token `captured`
/// (ADR 0067; §4 "A changed epoch token at commit aborts the transition").
async fn epoch_unchanged(
    state: &AppState,
    key: &str,
    captured: &x0x::groups::LifecycleEpochToken,
) -> bool {
    state
        .named_groups
        .read()
        .await
        .get(key)
        .map(GroupInfo::lifecycle_epoch_token)
        .as_ref()
        == Some(captured)
}

/// What [`arm_in_place`] found in the sidecar when it installed an ATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmSlot {
    Installed,
    /// A conflict is already recorded: nothing arms.
    Stopped,
    /// A verified active ATA diverges from this one: the conflict is
    /// recorded beside it.
    Conflict,
}

/// §2 "Arming" for a node whose record does not change at arming (the
/// request path, and a provisional signer whose path verified): under the
/// membership lock, re-check the epoch token, keep the ATA in the sidecar,
/// then write the placeholder. Returns whether the arming is published.
///
/// §2 "Conflict" (#1533 r8): the compare with the active ATA and the
/// install are one sidecar write (under the sidecar writer lock), so of
/// two conflicting replies that arrive together the second records the
/// conflict and never replaces the first. The callers' early checks only
/// save work.
async fn arm_in_place(
    state: &Arc<AppState>,
    group_key: &str,
    captured: &GroupInfo,
    ata: AdminTerminalAttestation,
) -> bool {
    let stable = captured.stable_group_id().to_string();
    let lock = super::group_membership_lock(state, group_key).await;
    let _membership_guard = lock.lock().await;
    if !epoch_unchanged(state, group_key, &captured.lifecycle_epoch_token()).await {
        tracing::info!(group_id = %LogHexId::group(group_key), "ADR 0109 S3: the group's epoch moved before arming; re-evaluated on the next answer");
        return false;
    }
    // §4 (D81): every arming path ends here, so the Home gate is checked
    // here too, on the record as it is under the lock. Nothing is written
    // for a Home-policy group: no sidecar and no placeholder.
    let home = is_home_policy_group(captured)
        || state
            .named_groups
            .read()
            .await
            .get(group_key)
            .is_none_or(is_home_policy_group);
    if home {
        return false;
    }
    // §4 "Timing": every arming path ends here, so the ADR 0094 host-commit
    // gate is checked here too. Nothing is written: no sidecar and no
    // placeholder.
    if defer_for_host_commit(state, &stable, captured.state_revision).await {
        return false;
    }
    let mut slot = ArmSlot::Installed;
    let candidate = ata.clone();
    let written = update_sidecar(state, &stable, |body| {
        // A diverging ATA is recorded even beside an earlier conflict: it
        // can bound the gate at a shorter prefix (#1533 rc15).
        if body
            .active_ata
            .as_ref()
            .is_some_and(|active| verified_conflict(active, &candidate, captured))
        {
            slot = ArmSlot::Conflict;
            keep_strongest_conflict(body, candidate);
        } else if body.attestation_conflict.is_some() {
            slot = ArmSlot::Stopped;
        } else {
            body.active_ata = Some(candidate);
        }
    })
    .await;
    match slot {
        ArmSlot::Installed if written => {}
        ArmSlot::Installed => return false,
        ArmSlot::Stopped => {
            show_conflict(state, captured).await;
            return false;
        }
        // The record only adds containment: when its write failed,
        // `record_conflict_locked` holds it in memory.
        ArmSlot::Conflict if !written => {
            record_conflict_locked(state, group_key, captured, ata).await;
            return false;
        }
        ArmSlot::Conflict => {
            announce_conflict(state, group_key, captured).await;
            return false;
        }
    }
    begin_placehold(state, group_key, captured);
    let outcome = super::save_named_groups_checked(state).await;
    let write = confirm_placeheld_write(state, &stable, LegacyWrite::of(&outcome));
    finish_arm(state, &stable, write, &ata).await
}

/// Write the legacy views again (the placeholder, or the real record once
/// a group is no longer placeheld).
async fn resave_legacy(state: &AppState) -> LegacyWrite {
    LegacyWrite::of(&super::save_named_groups_checked(state).await)
}

/// §4 at worker start and on every tick: make "placeheld" match "needs the
/// placeholder", and finish what load reconciliation and earlier
/// transitions left.
/// - A group that needs it and is not placeheld is registered (from its
///   durable authoritative record when the sidecar holds one) and its
///   legacy views are written again.
/// - A live record that is itself a placeholder while the sidecar holds an
///   authoritative record matched neither end at load: it stays inert and
///   placeheld (`lost`), and the node shows
///   `readmission_required {local_state_lost}` (§4 rebuild table).
/// - A group that no longer needs it is un-placeheld: the real record is
///   written to the legacy views, and only once that is durable are the
///   authoritative record dropped from the sidecar and the entry itself
///   removed — until then the group stays held back for the card routes
///   (#1570, 29 Oct 2026 ruling) and its owed card survives on the entry.
/// - A placeholder write that was not durable is written again.
///
/// The pass also retries the sidecar write of every held-back group
/// (#1570) and publishes each group's owed card once its hold has ended,
/// whichever save ended the hold.
pub(super) async fn ensure_placeholders(state: &Arc<AppState>) {
    let bodies: Vec<(String, GroupRecoveryV1)> = {
        let inner = state.group_recovery.inner.lock().await;
        inner
            .sidecars
            .iter()
            .filter(|(stable, body)| {
                !inner.sidecar_status.contains_key(*stable)
                    && (body.active_ata.is_some() || body.authoritative_record.is_some())
            })
            .map(|(stable, body)| (stable.clone(), body.clone()))
            .collect()
    };
    let registered = placeheld_snapshot(state);
    // #1570: the groups whose card a hold left owed. A hold can end in
    // any save's encode — every encode retries the sidecar write — so
    // the pass publishes every owed card whose hold has ended, not only
    // the holds this pass itself cleared.
    let owed_cards: Vec<String> = registered
        .iter()
        .filter(|(_, entry)| entry.card_owed)
        .map(|(stable, _)| stable.clone())
        .collect();
    if bodies.is_empty() && registered.is_empty() {
        return;
    }
    // #1533 r10: the live record of a staged re-seat is the staged join,
    // not the original that the placeholder protects. Its placeholder, and
    // the authoritative record behind it, stay as they are until the swap.
    let frozen = staging_frozen_groups(state).await;
    let live: HashMap<String, (String, GroupInfo)> = {
        let groups = state.named_groups.read().await;
        let mut live = HashMap::new();
        for (key, info) in groups.iter() {
            let stable = info.stable_group_id().to_string();
            let replace = live
                .get(&stable)
                .is_none_or(|(existing, _): &(String, GroupInfo)| key < existing);
            if replace {
                live.insert(stable, (key.clone(), info.clone()));
            }
        }
        live
    };
    let mut resave = false;
    let mut unplacehold = Vec::new();
    for (stable, body) in &bodies {
        if frozen.contains(stable) {
            continue;
        }
        let Some((key, info)) = live.get(stable) else {
            continue;
        };
        let lost = body.authoritative_record.is_some() && s3::is_s3_placeholder(info);
        let wanted = lost || needs_placeholder(state, info, body).await;
        let entry = registered.get(stable);
        if wanted {
            match entry {
                None => {
                    let durable_digest = body
                        .authoritative_record
                        .as_deref()
                        .map(|bytes| *blake3::hash(bytes).as_bytes());
                    // Load reconciliation spliced the record that the
                    // loaded placeholder names, so the legacy views hold
                    // its placeholder; with no authoritative record they
                    // hold the real record.
                    let committed = if durable_digest.is_some() && !lost {
                        LegacyForm::placeholder(info)
                    } else {
                        LegacyForm::real(info)
                    };
                    let key = key.clone();
                    with_placeheld(state, |placeheld| {
                        placeheld.insert(
                            stable.clone(),
                            Placeheld {
                                key,
                                committed,
                                encoded: None,
                                durable_digest,
                                authoritative_failed: false,
                                card_owed: false,
                                unplacehold_pending: false,
                                lost,
                                legacy_pending: true,
                            },
                        );
                    });
                    resave = true;
                }
                Some(entry) => {
                    // The group needs the placeholder again: an
                    // un-placeholdering that never landed is superseded.
                    with_placeheld(state, |placeheld| {
                        if let Some(entry) = placeheld.get_mut(stable) {
                            entry.unplacehold_pending = false;
                        }
                    });
                    resave |= entry.legacy_pending;
                }
            }
            if lost {
                set_view(
                    state,
                    stable,
                    info.state_revision,
                    SubjectView::Readmission {
                        cause: "local_state_lost",
                    },
                )
                .await;
            }
        } else if entry.is_some() || body.authoritative_record.is_some() {
            unplacehold.push(stable.clone());
        }
    }
    // A registered group whose sidecar no longer arms anything.
    for stable in registered.keys() {
        if !bodies.iter().any(|(held, _)| held == stable)
            && !unplacehold.contains(stable)
            && !frozen.contains(stable)
        {
            unplacehold.push(stable.clone());
        }
    }
    if !unplacehold.is_empty() {
        // #1570 (Engineer ruling, 29 Oct 2026): the entry stays, its
        // un-placeholdering pending, until this pass's write makes the
        // real record Durable. Until then the group stays held back for
        // the card routes and its owed card survives on the entry — the
        // flag is never lost with the entry. A group with no entry (only
        // a sidecar authoritative record) keeps the pre-#1570 behaviour:
        // nothing of it was ever held back.
        //
        // #1708 review (Codex P1, the two-save interleaving): the reset
        // joins the persistence transaction. Every save holds
        // `named_groups_persistence_lock` from its encode to its
        // `commit_legacy_write`, and a save between the two has already
        // recorded the group's newer real form in `encoded`. Resetting
        // that field outside the lock dropped the form, so the save's
        // Durable completion left `committed` at the older form and a
        // later held-back write could roll it over the newer durable
        // record. Under the lock the reset runs only between saves: the
        // parked save's commit consumes its own form first.
        //
        // #1708 review (Claude, REQUEST-CHANGES): the snapshot above can
        // be stale by now. An arming that started after it writes its
        // ATA, claims the placeholder ([`begin_placehold`]) and saves
        // under this same lock; resetting that group to pending here
        // would undo the arming. The resave would land the real record,
        // the retain would drop the entry, and the sidecar clear below
        // would strip the authoritative record while the ATA stays
        // armed. So under the lock each listed stable's sidecar is read
        // again: one whose body differs from the snapshot (an arming, a
        // conflict, a retirement, any sidecar transition) is left wholly
        // to the next pass, which decides on the fresh body.
        //
        // #1708 review (Codex P1, the post-reread arming): the re-read
        // and the reset are one step under the sidecar `inner` guard.
        // An arming's pre-save steps do not take the persistence lock:
        // it installs its ATA (under `inner`) and only then claims the
        // placeholder. With the guard released between the re-read and
        // the reset, both steps could land in that gap, and the reset
        // undid the new claim. Under the guard, an install either lands
        // before the re-read (the body differs, so the group is skipped)
        // or after the reset (its claim then supersedes the reset). Lock
        // order: persistence lock, `inner`, placeheld map.
        let _persistence_guard = state.named_groups_persistence_lock.lock().await;
        for stable in &unplacehold {
            let snapshot = bodies
                .iter()
                .find(|(held, _)| held == stable)
                .map(|(_, body)| body);
            let inner = state.group_recovery.inner.lock().await;
            if arms_snapshot(&inner, stable) != snapshot {
                continue;
            }
            #[cfg(test)]
            let mut inner = inner;
            #[cfg(test)]
            if let Some((reached, release)) = inner.pending_reread_pause.take() {
                reached.notify_one();
                release.notified().await;
            }
            with_placeheld(state, |placeheld| {
                if let Some(entry) = placeheld.get_mut(stable) {
                    entry.unplacehold_pending = true;
                    entry.authoritative_failed = false;
                    entry.card_owed = true;
                    entry.legacy_pending = true;
                    entry.encoded = None;
                }
            });
            drop(inner);
        }
        resave = true;
    }
    let write = if resave {
        Some(resave_legacy(state).await)
    } else {
        // Nothing to write this pass. Owed cards can still be due: a
        // hold that an earlier save ended leaves its card owed until a
        // pass publishes it (#1570).
        None
    };
    // #1708 review: an entry the retain below completes while it still
    // owes a card must not lose the flag with the entry; those stables
    // join the owed-card list below.
    let mut removed_owed: Vec<String> = Vec::new();
    if write == Some(LegacyWrite::Durable) {
        // #1708 review: a staged re-seat can freeze a group after the
        // pass's snapshot above. The retain and the sidecar clear below
        // must see it, or a frozen group's entry is dropped and its
        // authoritative record cleared on a stale set.
        let frozen = staging_frozen_groups(state).await;
        with_placeheld(state, |placeheld| {
            for entry in placeheld.values_mut() {
                if !entry.authoritative_failed {
                    entry.legacy_pending = false;
                }
            }
            // #1570: the write landed the real record of every group
            // whose un-placeholdering is pending (this pass's view held
            // it), so those entries complete and go; the owed-card loop
            // below publishes their cards. A group armed again meanwhile
            // or frozen for a staged re-seat keeps its entry.
            // #1708 review: the completed test also requires the
            // committed form to be the real record. The flag alone says
            // the pass wanted the real record; `committed` says a
            // Durable write landed it. A group whose real record is not
            // the durable form yet (its write is still in flight, or it
            // turned pending only after this pass's encode) keeps its
            // entry for the pass whose write does land it.
            placeheld.retain(|stable, entry| {
                let completed = entry.unplacehold_pending
                    && !entry.committed.placeholder
                    && !frozen.contains(stable);
                if completed && entry.card_owed {
                    removed_owed.push(stable.clone());
                }
                !completed
            });
        });
        for stable in unplacehold {
            // The real record is durable in the legacy views. A group that
            // was placeheld again meanwhile keeps its authoritative record.
            let _ = update_sidecar(state, &stable, |body| {
                if !is_placeheld(state, &stable) {
                    body.authoritative_record = None;
                    body.authoritative_binding = None;
                }
            })
            .await;
        }
    }
    // #1570: a hold kept the card routes on the group's last committed
    // form. Whichever save ended the hold, that form is durable now, so
    // the owed card is refreshed and published from the live record, as
    // a state change would refresh it. The check and the clear are one
    // step under the placeheld map, so a hold that starts again keeps
    // its own owed flag. A group whose un-placeholdering write has not
    // landed keeps its flag on the entry. A group missing from the live
    // map owes nothing: no card of it can be signed or published, so the
    // debt is cleared, not retried on every tick (#1708 review).
    // Detached: the publish's gossip egress must not stall the tick.
    // #1708 review: the pass's own un-placehold step (or a dropped
    // arming, [`finish_arm`]) can set the owed flag and the retain above
    // remove the entry in this same pass — the pre-pass snapshot cannot
    // hold those, so the completed entries join the list here.
    let mut owed_cards = owed_cards;
    owed_cards.extend(removed_owed);
    owed_cards.sort();
    owed_cards.dedup();
    for stable in owed_cards {
        let Some((key, _)) = live.get(&stable) else {
            with_placeheld(state, |placeheld| {
                if let Some(entry) = placeheld.get_mut(&stable) {
                    entry.card_owed = false;
                }
            });
            continue;
        };
        let publish_now = with_placeheld(state, |placeheld| match placeheld.get_mut(&stable) {
            Some(entry) if !entry.authoritative_failed && !entry.unplacehold_pending => {
                entry.card_owed = false;
                true
            }
            // A new hold started, or the un-placeholdering write has not
            // landed; its own owed flag stays set.
            Some(_) => false,
            // Un-placeheld by this pass's Durable write above; the same
            // write committed the real record, so the card is published
            // from it.
            None => write == Some(LegacyWrite::Durable),
        });
        if !publish_now {
            continue;
        }
        let state_for_card = Arc::clone(state);
        let key_for_card = key.clone();
        state.spawn_detached(async move {
            super::maybe_publish_group_card_after_state_change(
                state_for_card.as_ref(),
                &key_for_card,
            )
            .await;
        });
    }
}

// ─── §6 Guarded egress ─────────────────────────────────────────────────────

/// Which serving guard one response write uses (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    /// ADR 0107's serving guard plus D60: an Active, unbanned, unrevoked
    /// member of a group that is not withdrawn or quarantined.
    Member,
    /// The re-seat guard: not Active, not banned or revoked, holding the
    /// current unconsumed authorisation with this digest, from an issuer
    /// whose own record is uncontained, plus D60.
    Reseat([u8; 32]),
    /// A refusal carries no group state: D60 only.
    Refusal,
}

/// §5: only a current, verified, positive `group_terminal_attest_v1`
/// advert admits an S3 write. Unknown, expired or card-only support sends
/// nothing.
fn capability_admits(supported: Option<bool>) -> bool {
    supported == Some(true)
}

/// The sync part of [`contained`]: a marker or an owner-armed gap record
/// on the record itself (the seam cannot await).
fn record_contained(info: &GroupInfo) -> bool {
    info.fork_quarantine.is_some()
        || info
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
            .is_some_and(|record| {
                record.reason == s3::OWNER_ATTESTED_GAP_REASON
                    && info.state_revision < record.terminal_revision
            })
}

/// §6 at a re-seat write: the group is not withdrawn; the recipient is not
/// Active or banned; this node's own record (the issuer's) is not
/// contained; and the authorisation with `digest` is still issued to the
/// recipient (not consumed or replaced) and unexpired at `now_ms`.
fn reseat_write_admits(
    info: &GroupInfo,
    issuer_contained: bool,
    issued: &[IssuedReseatV1],
    recipient_hex: &str,
    digest: &[u8; 32],
    now_ms: u64,
) -> bool {
    !info.withdrawn
        && !info.has_active_member(recipient_hex)
        && !info.is_banned(recipient_hex)
        && !issuer_contained
        && issued.iter().any(|entry| {
            let fields = &entry.authorisation.fields;
            fields.subject.eq_ignore_ascii_case(recipient_hex)
                && fields.expires_at_ms > now_ms
                && entry.authorisation.digest() == *digest
        })
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
                let supported = state.agent.capability_store().verified_registry_supports(
                    &recipient,
                    x0x::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1,
                );
                if !capability_admits(supported) || !write_allowed(&state, &recipient).await {
                    return None;
                }
                match guard {
                    Guard::Member => {
                        super::join_artifact_serving_check(&state, &group_key, &recipient_hex)
                            .await
                            .ok()?
                    }
                    Guard::Reseat(digest) => {
                        let info = state.named_groups.read().await.get(&group_key).cloned()?;
                        let issuer_contained = contained(&state, &info).await;
                        let issued = issued_reseats(&state, info.stable_group_id()).await;
                        if !reseat_write_admits(
                            &info,
                            issuer_contained,
                            &issued,
                            &recipient_hex,
                            &digest,
                            now_ms(),
                        ) {
                            return None;
                        }
                        None
                    }
                    Guard::Refusal => None,
                }
            };
            let seam: x0x::dm::SeamAdmission = match guard {
                Guard::Member => Box::new(move || {
                    capability_admits(state.agent.capability_store().verified_registry_supports(
                        &recipient,
                        x0x::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1,
                    )) && super::join_artifact_seam_refusal(
                        &state,
                        &group_key,
                        &recipient_hex,
                        evidence,
                    )
                    .is_none()
                }),
                // Immediately before the write: the same checks again, from
                // the live roster and sidecar (busy locks fail closed).
                Guard::Reseat(digest) => Box::new(move || {
                    let supported = state.agent.capability_store().verified_registry_supports(
                        &recipient,
                        x0x::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1,
                    );
                    let Ok(groups) = state.named_groups.try_read() else {
                        return false;
                    };
                    let Some(info) = groups.get(&group_key) else {
                        return false;
                    };
                    let Ok(inner) = state.group_recovery.inner.try_lock() else {
                        return false;
                    };
                    let issued = inner
                        .sidecars
                        .get(info.stable_group_id())
                        .map(|body| body.issued_reseats.as_slice())
                        .unwrap_or_default();
                    capability_admits(supported)
                        && reseat_write_admits(
                            info,
                            record_contained(info),
                            issued,
                            &recipient_hex,
                            &digest,
                            now_ms(),
                        )
                }),
                Guard::Refusal => Box::new(move || {
                    capability_admits(state.agent.capability_store().verified_registry_supports(
                        &recipient,
                        x0x::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1,
                    ))
                }),
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

async fn issued_reseats(state: &AppState, stable_group_id: &str) -> Vec<IssuedReseatV1> {
    state
        .group_recovery
        .inner
        .lock()
        .await
        .sidecars
        .get(stable_group_id)
        .map(|body| body.issued_reseats.clone())
        .unwrap_or_default()
}

// ─── Receive ───────────────────────────────────────────────────────────────

/// The direct-message listener hands every `X0XGRC1` payload here.
pub(in crate::server) fn spawn_receipt(
    state: &Arc<AppState>,
    sender: AgentId,
    verified: bool,
    payload: Vec<u8>,
) {
    if !verified || !state.group_recovery.runs_s3() {
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
    let admission = state
        .group_recovery
        .inner
        .lock()
        .await
        .responder
        .admit(request.requester, now);
    let bytes = match admission {
        Admission::Drop => return,
        Admission::Refuse => {
            let response = response_for(
                &request,
                AttestAnswer::Refused(AttestRefusalReason::RateLimited),
            );
            send_response(state, &group_key, sender, Guard::Refusal, &response, false).await
        }
        Admission::Build => {
            let (answer, guard) = build_answer(state, &group_key, &request).await;
            let response = response_for(&request, answer);
            send_response(state, &group_key, sender, guard, &response, true).await
        }
    };
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
    // §5: an unknown advert asks for a refresh and sends nothing now; the
    // admission re-checks the advert under the membership lock.
    let sent = capability_admits(peer_capable(state, &recipient))
        && guarded_send(state, group_key, recipient, guard, &payload).await;
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
                Some(issued) => {
                    let digest = issued.authorisation.digest();
                    (
                        AttestAnswer::Reseat {
                            authorisation: Box::new(issued.authorisation),
                            invite: issued.invite,
                        },
                        Guard::Reseat(digest),
                    )
                }
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
                    remember_reseat_bases(state, &info, &requester_hex, request, true).await;
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
    // The re-seat route refuses a banned or revoked subject, so its refs
    // are never a basis.
    if !matches!(
        answer,
        AttestAnswer::Refused(AttestRefusalReason::BannedOrRevoked)
    ) {
        remember_reseat_bases(state, &info, &requester_hex, request, false).await;
    }
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
///
/// §11 (D83) bounds this per group: each subject keeps at most
/// `RECOVERY_LIST_CAP` refs and the group at most `RECOVERY_LIST_CAP`
/// subjects. Over the cap, the least recent subject that has no roster
/// entry goes first, so fresh keys cannot push out a removed member.
async fn remember_reseat_bases(
    state: &AppState,
    info: &GroupInfo,
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
    let stable = info.stable_group_id().to_string();
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    let entry = inner
        .reseat_bases
        .entry((stable.clone(), subject_hex.to_string()))
        .or_insert_with(|| ReseatBases {
            refs: Vec::new(),
            at: now,
        });
    entry.at = now;
    for recovery_ref in refs {
        if !entry.refs.contains(&recovery_ref) {
            entry.refs.push(recovery_ref);
        }
    }
    let excess = entry.refs.len().saturating_sub(s3::RECOVERY_LIST_CAP);
    entry.refs.drain(..excess);
    loop {
        let mut subjects: Vec<(bool, Instant, String)> = inner
            .reseat_bases
            .iter()
            .filter(|((group, _), _)| *group == stable)
            .map(|((_, subject), bases)| {
                (
                    // #1578 rc11 (audit): the join's key-only marker
                    // row is not a seat — the subject stays a stranger,
                    // exactly main's roster.
                    info.members_v2.contains_key(subject)
                        && !info.join_seat_key_marker_only(subject),
                    bases.at,
                    subject.clone(),
                )
            })
            .collect();
        if subjects.len() <= s3::RECOVERY_LIST_CAP {
            break;
        }
        // Strangers before roster subjects, then the least recent first.
        subjects.sort();
        let Some((_, _, evict)) = subjects.into_iter().next() else {
            break;
        };
        inner.reseat_bases.remove(&(stable.clone(), evict));
    }
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
    if owner_terminal_served || chain.is_empty() || !state.group_recovery.runs_s3() {
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
    terminal_event: &super::NamedGroupMetadataEvent,
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
    if defer_for_host_commit(state, &stable, current.state_revision).await {
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
    // Signer eligibility: verified on this node's roster, or provisional
    // with a promotion path inside the walked served chain. A provisional
    // ATA whose path does not verify has no authority at all: it arms
    // nothing and causes no conflict (§2), so it is checked first.
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
    if owner_armed
        || armed_admin_ata(state, &current).await.is_some()
        || conflict_recorded(state, &stable).await
    {
        return false;
    }
    // The armed admin record lives in the S3 sidecar (`active_ata`), never
    // in `invite_lineage.anchored_gap_refusal` (David's ruling 3, 21 Oct
    // 2026). A released binary keeps its containment through the §4
    // placeholder that the legacy write below carries.
    let captured_epoch = current.lifecycle_epoch_token();
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
    let mut applied_links = 0usize;
    for (index, link) in chain.iter().take(segment_links).enumerate() {
        // §2: past the promotion prefix, each link needs the signer's
        // Active admin seat on the record the earlier links left.
        if index >= armed_from && !attested_link_admitted(ata, &next, &link.commit) {
            tracing::info!(group_id = %LogHexId::group(&group_key), revision = link.commit.revision, "ADR 0109 S3: the signer has no Active admin seat after the applied links; the rest of the batch is refused");
            break;
        }
        match s3::apply_link_state_only(&next, link) {
            Ok(applied) => {
                next = applied;
                applied_links += 1;
            }
            Err(reason) => {
                tracing::info!(group_id = %LogHexId::group(&group_key), reason, revision = link.commit.revision, "ADR 0109 S3: attested link refused");
                return false;
            }
        }
    }
    if applied_links == 0 {
        return false;
    }
    // Keep the served chain, the ATA and the terminal event beside the
    // record (§4). The event is what a later segment replays when this
    // segment ends before the terminal (§2 "Segments").
    let served_json: Vec<Vec<u8>> = chain
        .iter()
        .filter_map(|link| serde_json::to_vec(link).ok())
        .collect();
    let ata_kept = ata.clone();
    let terminal_json = serde_json::to_vec(terminal_event).ok();
    // #1533 r11: the armed and conflict checks above read a snapshot; a
    // reply can arm another ATA or record a conflict before this write.
    // Check both again on the latest sidecar: a conflict, or another armed
    // ATA, keeps its state and this carry does not apply.
    let carried = update_sidecar_if(state, &stable, |body| {
        let other_armed = body
            .active_ata
            .as_ref()
            .is_some_and(|active| active != &ata_kept && armed_on(active, &current));
        if body.attestation_conflict.is_some() || other_armed {
            return false;
        }
        body.served_chain = served_json;
        body.active_ata = Some(ata_kept);
        body.queued_terminal = terminal_json;
        true
    })
    .await;
    match carried {
        SidecarWrite::Written => {}
        SidecarWrite::Declined => {
            tracing::info!(group_id = %LogHexId::group(&group_key), "ADR 0109 S3: a conflict or another armed ATA arrived first; join carry not applied");
            return false;
        }
        SidecarWrite::NotDurable => {
            tracing::warn!(group_id = %LogHexId::group(&group_key), "ADR 0109 S3: sidecar not durable; join carry not applied");
            return false;
        }
    }
    // §4 "Transactions": the sidecar (above, and the authoritative record
    // inside the roster save) first, then the legacy views with the S3
    // placeholder, bound to the epoch token captured under this lock.
    let write = if epoch_unchanged(state, &group_key, &captured_epoch).await {
        begin_placehold(state, &group_key, &current);
        let outcome = super::persist_named_group_info(state, &group_key, next.clone()).await;
        confirm_placeheld_write(state, &stable, LegacyWrite::of(&outcome))
    } else {
        LegacyWrite::Dropped
    };
    // #1570: a `Dropped` from `confirm_placeheld_write` follows a Durable
    // save, which published `next`; `unpublish_not_durable` takes it back
    // (it changes nothing when the live record is no longer `next`).
    if write != LegacyWrite::Durable {
        unpublish_not_durable(state, &group_key, &current, &next).await;
    }
    if !finish_arm(state, &stable, write, ata).await {
        tracing::warn!(group_id = %LogHexId::group(&group_key), "ADR 0109 S3: attested links not durable");
        return false;
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

/// ADR 0109 §2 per-link signer eligibility, the one check that the join
/// carry and the catch-up page path both use: "If the signer stops being
/// an active admin after an applied link, the gate stops there". `current`
/// is the record after the links applied so far. `link` may apply only
/// while the signer is an Active admin on `current` and `link` is the next
/// hash of the ATA's sequence after the head.
fn attested_link_admitted(
    ata: &AdminTerminalAttestation,
    current: &GroupInfo,
    link: &GroupStateCommit,
) -> bool {
    // A signer without the seat gets only the links already applied, so
    // no next hash is in the gate sequence.
    let Some(sequence) = s3::armed_gate_sequence(ata, current) else {
        return false;
    };
    s3::next_gate_hash(&ata.fields.from_state_hash, &sequence, &current.state_hash)
        .is_some_and(|hash| *hash == link.state_hash)
}

/// ADR 0109 §2 "Conflict": "Nothing past the common prefix applies". This
/// is the one conflict gate. The metadata apply
/// (`apply_named_group_metadata_event_inner_serialized`) calls it for
/// every commit, under the group's membership lock and on the record it
/// loaded under that lock, so a catch-up page, a DM and a gossip delivery
/// have the same bound. The ADR 0110 S4 receivers (certificate rebind,
/// crypto-only exclusion and owner recovery) apply their commits outside
/// that path, so each calls it under the same lock before it keeps the
/// frame (#1533 r6). A commit that does not advance the head
/// (`revision <= current.state_revision`) passes: the apply refuses it or
/// installs a marker through the existing path ("Conflicting commits still
/// install a marker"). A commit that advances the head applies only when
/// it is the next hash of the common prefix ([`s3::conflict_admits_link`]).
/// At start the gate waits until the sidecars are restored
/// ([`restore_containment`], #1533 r8).
pub(super) async fn conflict_admits_commit(
    state: &AppState,
    current: &GroupInfo,
    commit: &GroupStateCommit,
) -> bool {
    if commit.revision <= current.state_revision {
        return true;
    }
    state.group_recovery.wait_restored().await;
    conflict_admits_head(state, current, commit).await
}

/// The bound itself, on the restored sidecar map.
async fn conflict_admits_head(
    state: &AppState,
    current: &GroupInfo,
    commit: &GroupStateCommit,
) -> bool {
    let Some(body) = sidecar_snapshot(state, current.stable_group_id()).await else {
        return true;
    };
    match (body.active_ata.as_ref(), body.attestation_conflict.as_ref()) {
        (Some(active), Some(conflict)) => {
            s3::conflict_admits_link(active, conflict, &current.state_hash, &commit.state_hash)
        }
        // #1533 r11: a conflict keeps its ATA until a re-seat. A conflict
        // without it has no common prefix to bound, so nothing past the
        // head applies (fail closed) rather than everything.
        (None, Some(_)) => false,
        (_, None) => true,
    }
}

/// ADR 0109 §2 "Conflict" for a commit this node authors (#1533 r8): the
/// same bound as [`conflict_admits_commit`], checked in
/// `seal_commit_owner_certified` and the other local seal sites, so no
/// local author seals past the common prefix. `before` is the record as
/// it was before the seal. The callers hold the roster lock, so this never
/// waits for the restore: before the sidecars are restored it refuses.
pub(in crate::server) async fn local_seal_admitted(
    state: &AppState,
    before: &GroupInfo,
    commit: &GroupStateCommit,
) -> bool {
    if commit.revision <= before.state_revision {
        return true;
    }
    if !state.group_recovery.is_restored() {
        tracing::warn!(group_id = %LogHexId::group(before.stable_group_id()), "ADR 0109 S3: a local seal before the sidecars are restored is refused");
        return false;
    }
    conflict_admits_head(state, before, commit).await
}

/// The catch-up page side of [`attested_link_admitted`]: before each
/// commit of a page that the admin-armed gate admitted, read the record
/// that the earlier commits left and check the armed ATA on it again. The
/// page gate is checked once for the page; this check is per commit.
pub(super) async fn armed_page_link_admitted(
    state: &AppState,
    group_id: &str,
    link: &GroupStateCommit,
) -> bool {
    let Some(group_key) = super::resolve_named_group_storage_key(state, group_id).await else {
        return false;
    };
    let Some(current) = state.named_groups.read().await.get(&group_key).cloned() else {
        return false;
    };
    let Some(ata) = armed_admin_ata(state, &current).await else {
        return false;
    };
    attested_link_admitted(&ata, &current, link)
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
    let kept: Vec<RetainedCommit> = body
        .served_chain
        .iter()
        .filter_map(|bytes| serde_json::from_slice(bytes).ok())
        .collect();
    if kept.is_empty() {
        return false;
    }
    // §2 "Segments": after an earlier segment the head is inside the kept
    // chain; only the links after it are still to apply.
    let Some(chain) = s3::kept_chain_remainder(kept, info.state_revision, &info.state_hash) else {
        return false;
    };
    let (Some(terminal), Some(actor)) = (
        super::named_group_metadata_event_commit(&event).cloned(),
        match &event {
            super::NamedGroupMetadataEvent::MemberAdded { actor, .. } => parse_raw(actor),
            _ => None,
        },
    ) else {
        return false;
    };
    if !Box::pin(apply_join_carry(
        state, group_key, &chain, &terminal, &event, ata,
    ))
    .await
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

/// §2 "Segments": the admin-armed ATA's segment is exhausted (the head is
/// its last hash) while the kept terminal is still ahead. The gate stays
/// armed with an empty remaining sequence, which admits nothing, and the
/// node asks for the next segment from its head. Returns the kept
/// terminal's `(revision, state_hash)`.
async fn exhausted_segment(state: &AppState, info: &GroupInfo) -> Option<(u64, String)> {
    let body = sidecar_snapshot(state, info.stable_group_id()).await?;
    let ata = body.active_ata?;
    let at_end = info.state_revision == ata.fields.segment_terminal_revision
        && ata.fields.sequence.last() == Some(&info.state_hash);
    if !at_end {
        return None;
    }
    let event =
        serde_json::from_slice::<super::NamedGroupMetadataEvent>(body.queued_terminal.as_deref()?)
            .ok()?;
    let terminal = super::named_group_metadata_event_commit(&event)?;
    (terminal.revision > info.state_revision)
        .then(|| (terminal.revision, terminal.state_hash.clone()))
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
    armed_on(&ata, info).then_some(ata)
}

/// Whether `ata` is armed on `info`: the head is on its sequence (or is
/// its `from`) and its segment terminal is not yet reached.
fn armed_on(ata: &AdminTerminalAttestation, info: &GroupInfo) -> bool {
    let on_sequence = info.state_hash == ata.fields.from_state_hash
        || ata.fields.sequence.contains(&info.state_hash);
    on_sequence && info.state_revision < ata.fields.segment_terminal_revision
}

/// The #846 gate under an admin-armed ATA (§2): `Some(sequence)` while
/// armed. The caller requires each catch-up page to stay inside it. An
/// exhausted segment keeps the gate armed: the head is the sequence's last
/// hash, so no page link fits and the gate admits nothing until the next
/// segment arms (§2 "Segments"). A recorded conflict's bound is not
/// checked here: [`conflict_admits_commit`] checks it for every route.
pub(super) async fn armed_admin_sequence(
    state: &AppState,
    info: &GroupInfo,
) -> Option<Vec<String>> {
    if let Some(ata) = armed_admin_ata(state, info).await {
        // §2: when an applied link left the signer without an Active admin
        // seat, the gate stops at the head.
        return s3::armed_gate_sequence(&ata, info).or(Some(Vec::new()));
    }
    exhausted_segment(state, info).await?;
    sidecar_snapshot(state, info.stable_group_id())
        .await?
        .active_ata
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
    } else if let Some((terminal_revision, terminal_state_hash)) =
        exhausted_segment(state, info).await
    {
        refs.push(RecoveryRef::Gap {
            reason: s3::ADMIN_ATTESTED_GAP_REASON.to_string(),
            head_state_hash: info.state_hash.clone(),
            terminal_revision,
            terminal_state_hash,
        });
    }
    refs
}

/// Retire the admin-armed ATA once its exact segment terminal is durably
/// applied (§2 "Retirement"), with the S3 state that went with it. A
/// marker's retirement never touches it. It never clears a marker itself:
/// a marker that retires under this ATA retires first, by its own rule.
pub(super) async fn retire_converged(state: &Arc<AppState>, group_id: &str) {
    let Some(group_key) = super::resolve_named_group_storage_key(state, group_id).await else {
        return;
    };
    let Some(info) = state.named_groups.read().await.get(&group_key).cloned() else {
        return;
    };
    let stable = info.stable_group_id().to_string();
    let Some(body) = sidecar_snapshot(state, &stable).await else {
        return;
    };
    // §2 "Conflict": the conflict and its ATA stay until a re-seat.
    if body.attestation_conflict.is_some() {
        return;
    }
    let Some(ata) = body.active_ata else {
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
    if exhausted_segment(state, &info).await.is_some() {
        // A segment end before the terminal: keep the served chain and the
        // terminal for the next segment, and ask for it (§2 "Segments").
        let now = Instant::now();
        let mut inner = state.group_recovery.inner.lock().await;
        let subject = inner
            .subjects
            .entry(stable.clone())
            .or_insert_with(|| SubjectState::new(now, info.state_revision));
        if !subject.view.sticky() {
            subject.view = SubjectView::Awaiting {
                reason: "segment_exhausted".to_string(),
            };
        }
        return;
    }
    // §2 "Retirement": the marker's retirement needs the ATA, so a
    // matching marker retires first, durably. When it does not, the ATA
    // stays and the worker tries again. A crash after the marker retires
    // keeps the ATA (its head is on the sequence), and the next pass
    // retires it here. A sibling marker does not match and is untouched.
    if marker_retires_under(&info, &ata) && !retire_marker_attested(state, &group_key, &info).await
    {
        return;
    }
    // #1533 r11: a reply can record a conflict, or replace the ATA, after
    // the snapshot above. Retire only the ATA that converged, and never
    // under a recorded conflict, which keeps its ATA until a re-seat.
    let retired = update_sidecar_if(state, &stable, |body| {
        if body.attestation_conflict.is_some() || body.active_ata.as_ref() != Some(&ata) {
            return false;
        }
        body.served_chain.clear();
        body.active_ata = None;
        body.queued_terminal = None;
        true
    })
    .await;
    if retired != SidecarWrite::Written {
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

/// §2 "Conflict" and §4 at start (#1533 r8): load and reconcile the
/// sidecars once, then open the conflict gates. The daemon awaits this
/// before it starts any listener or worker that can apply or seal a
/// commit, so a conflict on disk bounds the first commit. The worker calls
/// it too; a second call waits for the first.
pub(in crate::server) async fn restore_containment(state: &AppState) {
    let runtime = &state.group_recovery;
    if runtime
        .restore_started
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        runtime.wait_restored().await;
        return;
    }
    load_sidecars(state).await;
    reconcile_loaded_atas(state).await;
    runtime.restored.send_replace(true);
}

/// The S3 worker: loads the sidecars, resumes re-seat journals, then runs
/// the subject's request loop and the staged-join progress check. Runs
/// until shutdown.
pub(in crate::server) async fn run_group_recovery_worker(state: Arc<AppState>) {
    restore_containment(&state).await;
    resume_journals(&state).await;
    ensure_placeholders(&state).await;
    let mut interval = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            biased;
            () = state.shutdown_started.cancelled() => break,
            _ = interval.tick() => {}
        }
        resume_deferred_quarantine(&state).await;
        reseat_progress(&state).await;
        subject_tick(&state).await;
        ensure_placeholders(&state).await;
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
    inner
        .reseat_bases
        .retain(|_, bases| now.saturating_duration_since(bases.at) < s3::RECOVERY_LIST_TTL);
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
        // An expired entry stays for `RESEAT_SEAL_RETENTION_MS` more, so
        // a seal of its invite still finds it and refuses (§3a); every
        // other reader treats it as expired.
        let gone = |issued: &IssuedReseatV1| {
            issued
                .authorisation
                .fields
                .expires_at_ms
                .saturating_add(RESEAT_SEAL_RETENTION_MS)
                <= now_wall
                || seated.contains(&issued.authorisation.fields.subject)
        };
        let due = {
            let inner = state.group_recovery.inner.lock().await;
            inner
                .sidecars
                .get(&group)
                .is_some_and(|body| body.issued_reseats.iter().any(gone))
        };
        if due {
            let _ = update_sidecar(state, &group, |body| {
                body.issued_reseats.retain(|issued| !gone(issued));
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
        if conflict_recorded(state, &stable).await {
            // After a restart the view is re-derived from the durable
            // conflict (§2 "Conflict", §8).
            show_conflict(state, &info).await;
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
        // §4 "Timing", H-S3-t (4): no request before host commit, since
        // its answer would create the sidecar.
        if defer_for_host_commit(state, &stable, info.state_revision).await {
            continue;
        }
        if local_state_lost(state, &key, &info, now).await {
            continue;
        }
        provisional_tick(state, &key, &info).await;
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
    if info.fork_quarantine.is_none() {
        return false;
    }
    // #1533 rc17 (Codex P2): [`record_conflict`] writes under the group's
    // membership lock. Hold it from the conflict check below until the
    // marker is durably cleared, so no conflict is recorded between the
    // check and the clear. The record and the sidecar are read again under
    // the lock; the caller's copies are only a fast path.
    let lock = super::group_membership_lock(state, group_key).await;
    let membership_guard = lock.lock().await;
    let Some(info) = state.named_groups.read().await.get(group_key).cloned() else {
        return false;
    };
    let Some(marker) = info.fork_quarantine.as_ref() else {
        return false;
    };
    let stable = info.stable_group_id().to_string();
    let Some(body) = sidecar_snapshot(state, &stable).await else {
        return false;
    };
    // §2 "Conflict": automatic recovery stops; nothing retires.
    if body.attestation_conflict.is_some() {
        return false;
    }
    let Some(ata) = body.active_ata else {
        return false;
    };
    if !marker_retires_under(&info, &ata) {
        return false;
    }
    let identity = RecoveryRef::from_marker(marker);
    let key = group_key.to_string();
    // ADR 0109 §4: S3 publishes only a Durable write. A not-durable write
    // keeps the marker live, and the worker retries.
    let outcome = super::persist_named_groups_quarantine_clear_durable_only(state, move |groups| {
        let Some(info) = crate::server::resolve_group_entry_mut_locked(groups, &key) else {
            return false;
        };
        // #1533 review: the record can change after the snapshot above (a
        // re-seat rollback restores the original with the same marker and
        // without the evidenced commit). Re-check the retirement rule on
        // the record that the write changes.
        let same = info
            .fork_quarantine
            .as_ref()
            .is_some_and(|marker| RecoveryRef::from_marker(marker) == identity)
            && marker_retires_under(info, &ata);
        if same {
            info.fork_quarantine = None;
            info.reset_fork_evidence_after_quarantine_clear();
        }
        same
    })
    .await;
    // The ingest resume takes the task-list locks before `named_groups`,
    // so it runs without the membership lock.
    drop(membership_guard);
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

/// §2 "Retirement": `info`'s marker retires under `ata`. Its evidenced
/// commit `(revision, state_hash, committed_by)` is applied, on the ATA's
/// sequence, and the signer is verified.
fn marker_retires_under(info: &GroupInfo, ata: &AdminTerminalAttestation) -> bool {
    let Some(marker) = info.fork_quarantine.as_ref() else {
        return false;
    };
    info.commit_log.iter().any(|entry| {
        entry.commit.revision == marker.revision
            && entry.commit.state_hash == marker.state_hash
            && entry
                .commit
                .committed_by
                .eq_ignore_ascii_case(&marker.committed_by)
    }) && ata.fields.sequence.contains(&marker.state_hash)
        && ata.signer_verified_on(info)
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
    let exhausted = exhausted_segment(state, info).await.is_some();
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
    // The node left the head its last request named. §2 drops an answer
    // for an old head, so a request still open is void, and the last
    // round's silence was for that head: its backoff does not hold here.
    // The round starts again from the first target once a responder's
    // per-requester interval (§11) has passed since that request, so the
    // new head's request is not refused `rate_limited` (#1726).
    if let Some((_, asked_at)) = subject
        .asked_from
        .take_if(|(head, _)| *head != info.state_hash)
    {
        subject.pending = None;
        subject.next_target = 0;
        subject.cooled = None;
        subject.next_retry_at = now.max(asked_at + s3::RESPONDER_PER_REQUESTER_INTERVAL);
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
    if exhausted {
        // §2 "Segments": the next segment is due now, not after a stall.
        if !subject.view.sticky() {
            subject.view = SubjectView::Awaiting {
                reason: "segment_exhausted".to_string(),
            };
        }
    } else if gap_only {
        if now.saturating_duration_since(subject.progress_at) < stall {
            return None;
        }
        if admin_armed && !subject.view.sticky() {
            subject.view = SubjectView::Awaiting {
                reason: "renewal_due".to_string(),
            };
        }
    }
    if let Some((_, asked_at, _)) = subject.pending {
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
    subject.pending = Some((*target.as_bytes(), now, info.state_hash.clone()));
    subject.asked_from = Some((info.state_hash.clone(), now));
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
    if !state.group_recovery.runs_s3() {
        return;
    }
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
    // A manual re-seat is not Home activation (§4): it runs before the
    // Home gate (see `consume_reseat`).
    if let AttestAnswer::Reseat {
        authorisation,
        invite,
    } = response.answer
    {
        consume_reseat(state, &group_key, *authorisation, invite).await;
        return;
    }
    // §4 (D81): Home activation ships off. A Home-policy group takes no
    // other answer, asked for or not: no ATA arms it, as on the issuing and
    // requesting paths (`answer_request`, `subject_tick`).
    if is_home_policy_group(&info) {
        tracing::info!(group_id = %LogHexId::group(&group_key), "ADR 0109 S3: answer for a Home-policy group ignored (Home activation is off)");
        return;
    }
    let stable = info.stable_group_id().to_string();
    let sender_hex = hex::encode(sender.as_bytes());
    let answer_name = response.answer.name().to_string();
    // Every other answer is for this node's current head only.
    if response.for_head_state_hash != info.state_hash {
        return;
    }
    let refs = live_refs(state, &info).await;
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    // #1533 r10: only the reply of the target this node asked, for the
    // head it asked about, moves the recovery state. A signed ATA carries
    // its own authority (`arm_from_response` verifies it), as does a
    // re-seat offer (above). Any other answer is the sender's word alone,
    // so an unsolicited one (from any verified peer that knows the group
    // and the head) changes nothing: no view, no round and no backoff.
    let from_pending = inner.subjects.get(&stable).is_some_and(|subject| {
        subject.pending.as_ref().is_some_and(|(target, _, head)| {
            target == sender.as_bytes() && *head == response.for_head_state_hash
        })
    });
    if !from_pending && !matches!(response.answer, AttestAnswer::Attested(_)) {
        return;
    }
    let subject = inner
        .subjects
        .entry(stable.clone())
        .or_insert_with(|| SubjectState::new(now, info.state_revision));
    if from_pending {
        subject.asked.insert(sender_hex, answer_name);
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
                    if every_reached_admin_beyond_retention(&subject.asked, |agent| {
                        roster_admin(&info, agent)
                    }) {
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
                    let target = *sender.as_bytes();
                    if other == AttestRefusalReason::RateLimited
                        && from_pending
                        && subject.cooled != Some(target)
                    {
                        cool_down(subject, target, now);
                    } else {
                        advance_round(subject, now, from_pending);
                    }
                }
            }
        }
        AttestAnswer::Reseat { .. } => {}
    }
}

/// §3 "Beyond retention" (D97): the node enters `readmission_required`
/// when every admin it has *reached* refuses with `base_beyond_retention`
/// and none attests. Only targets that are admins on this node's roster
/// (`is_admin`) count, so a member's answer never decides the state. An
/// admin that never answered (`pending`) was not reached, and one that
/// answers `not_an_admin` is no longer an admin; neither blocks the state.
/// An unreachable admin may still attest later, which leaves the state
/// (§8).
fn every_reached_admin_beyond_retention(
    asked: &BTreeMap<String, String>,
    is_admin: impl Fn(&str) -> bool,
) -> bool {
    let mut reached = asked
        .iter()
        .filter(|(agent, answer)| {
            is_admin(agent) && !matches!(answer.as_str(), "pending" | "not_an_admin")
        })
        .peekable();
    reached.peek().is_some() && reached.all(|(_, answer)| answer == "base_beyond_retention")
}

/// `agent_hex` is an Active admin on `info`'s roster.
fn roster_admin(info: &GroupInfo, agent_hex: &str) -> bool {
    info.members_v2
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(agent_hex))
        .is_some_and(|(_, member)| {
            member.is_active() && member.role.at_least(x0x::groups::GroupRole::Admin)
        })
}

/// §2 "Conflict": this node holds a recorded attestation conflict.
async fn conflict_recorded(state: &AppState, stable: &str) -> bool {
    sidecar_snapshot(state, stable)
        .await
        .is_some_and(|body| body.attestation_conflict.is_some())
}

/// Show `reseat_required {attestation_conflict}` unless a re-seat is
/// already under way.
async fn show_conflict(state: &AppState, info: &GroupInfo) {
    let stable = info.stable_group_id().to_string();
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    let subject = inner
        .subjects
        .entry(stable)
        .or_insert_with(|| SubjectState::new(now, info.state_revision));
    if matches!(
        subject.view,
        SubjectView::ReseatInProgress { .. }
            | SubjectView::Reseat {
                cause: "attestation_conflict",
                ..
            }
    ) {
        return;
    }
    subject.view = SubjectView::Reseat {
        cause: "attestation_conflict",
        recovery_ref: RecoveryRef::live_refs(info).into_iter().next(),
    };
}

/// §2 "Conflict": two valid ATAs for this node's chain diverge. Record the
/// second one beside the active ATA so the catch-up gate stops at their
/// common prefix ([`s3::conflict_gate_sequence`]), and enter
/// `reseat_required {attestation_conflict}`. The record only adds
/// containment, so when its durable write fails it is still held in
/// memory (the gate honours it now, and the next sidecar write carries
/// it). Two replies can both reach this point, so the record keeps the
/// strongest bound ([`keep_strongest_conflict`]) in both writes.
///
/// The caller compared `conflict` with a snapshot of the active ATA. The
/// write checks again on the latest sidecar (#1533 r11): a conflict is
/// recorded only beside an active ATA that it still diverges from, whose
/// signer is verified on `info`. A conflict without its active ATA has no
/// common prefix to bound; when the ATA was retired or replaced meanwhile,
/// nothing is recorded and the next answer is evaluated on the new head.
///
/// The record is written under the group's membership lock (#1533 rc15).
/// A local commit holds that lock from `local_seal_admitted` until it is
/// saved and published, so no local commit passes the conflict bound and
/// then installs past a common prefix recorded meanwhile.
async fn record_conflict(
    state: &AppState,
    group_key: &str,
    info: &GroupInfo,
    conflict: AdminTerminalAttestation,
) {
    let lock = super::group_membership_lock(state, group_key).await;
    let _membership_guard = lock.lock().await;
    record_conflict_locked(state, group_key, info, conflict).await;
}

/// [`record_conflict`] for a caller that holds the membership lock.
async fn record_conflict_locked(
    state: &AppState,
    group_key: &str,
    info: &GroupInfo,
    conflict: AdminTerminalAttestation,
) {
    let stable = info.stable_group_id().to_string();
    let still_diverges = |body: &GroupRecoveryV1, candidate: &AdminTerminalAttestation| {
        body.active_ata.as_ref().is_some_and(|active| {
            active.conflicts_with(candidate) && active.signer_verified_on(info)
        })
    };
    let kept = conflict.clone();
    let written = update_sidecar_if(state, &stable, |body| {
        if !still_diverges(body, &kept) {
            return false;
        }
        keep_strongest_conflict(body, kept);
        true
    })
    .await;
    match written {
        SidecarWrite::Written => {
            announce_conflict(state, group_key, info).await;
            return;
        }
        SidecarWrite::Declined => {
            tracing::info!(group_id = %LogHexId::group(group_key), "ADR 0109 S3: the active ATA changed before the conflict was recorded; the answer is evaluated again");
            return;
        }
        SidecarWrite::NotDurable => {}
    }
    tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0109 S3: the attestation conflict is not durable yet; it is held in memory");
    {
        let _writer = state.group_recovery.writer.lock().await;
        let mut inner = state.group_recovery.inner.lock().await;
        if !inner.sidecar_status.contains_key(&stable) {
            let body = inner.sidecars.entry(stable.clone()).or_default();
            if !still_diverges(body, &conflict) {
                return;
            }
            keep_strongest_conflict(body, conflict);
        }
    }
    announce_conflict(state, group_key, info).await;
}

/// §2 "Conflict": "Nothing past the common prefix applies", for every
/// conflict recorded. `candidate` replaces the recorded conflict only when
/// its common prefix with the active ATA is shorter, so a later record
/// never moves the bound forward (#1533 r9). Without an active ATA the
/// recorded conflict stays.
fn keep_strongest_conflict(body: &mut GroupRecoveryV1, candidate: AdminTerminalAttestation) {
    let replace = match (body.active_ata.as_ref(), body.attestation_conflict.as_ref()) {
        (_, None) => true,
        (Some(active), Some(recorded)) => {
            conflict_prefix_len(active, &candidate) < conflict_prefix_len(active, recorded)
        }
        (None, Some(_)) => false,
    };
    if replace {
        body.attestation_conflict = Some(candidate);
    }
}

/// The length of the common prefix of `active` and `conflict`. Two ATAs
/// that agree bound the gate at the head ([`s3::conflict_gate_sequence`]),
/// which is never weaker than a prefix, so they count as 0.
fn conflict_prefix_len(
    active: &AdminTerminalAttestation,
    conflict: &AdminTerminalAttestation,
) -> usize {
    active
        .divergence_from(conflict)
        .map_or(0, |prefix| prefix.len())
}

/// Show and log a recorded attestation conflict.
async fn announce_conflict(state: &AppState, group_key: &str, info: &GroupInfo) {
    show_conflict(state, info).await;
    tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0109 S3: conflicting admin attestations; automatic catch-up stops at their common prefix (reseat_required)");
}

/// §2 "Conflict": `candidate` diverges from `active` and both signers are
/// verified on `roster`. A provisional ATA causes no conflict, and nor does
/// an active ATA whose signer an applied link demoted.
fn verified_conflict(
    active: &AdminTerminalAttestation,
    candidate: &AdminTerminalAttestation,
    roster: &GroupInfo,
) -> bool {
    active.conflicts_with(candidate)
        && candidate.signer_verified_on(roster)
        && active.signer_verified_on(roster)
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

/// A `rate_limited` refusal from the asked target: ask that target again
/// once its per-requester interval (§11) has passed, in this round. The
/// responder starts that interval when it admits a request, which can be
/// later than this node sent it, so the restart in [`next_target`] can
/// still reach it too early (#1726). The interval started before the
/// refusal was sent, so it has passed one interval after the refusal
/// arrives. One cooldown per target per round: a second refusal moves the
/// round on, so the round still ends and backs off.
fn cool_down(subject: &mut SubjectState, target: [u8; 32], now: Instant) {
    subject.cooled = Some(target);
    subject.next_retry_at = now + s3::RESPONDER_PER_REQUESTER_INTERVAL;
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
        // A provisional ATA causes no conflict (§2): only a verified
        // signer's diverging sequence stops automatic catch-up. An active
        // ATA whose signer an applied link demoted has stopped (§2) and no
        // longer attests its remaining links, so it causes none either.
        // This runs before the recorded-conflict stop, so a later conflict
        // with a shorter common prefix still narrows the gate (#1533 rc15).
        if verified_conflict(&active, &ata, info) {
            record_conflict(state, group_key, info, ata).await;
            return;
        }
    }
    if conflict_recorded(state, &stable).await {
        // Automatic catch-up stopped at the conflict; no ATA arms again.
        show_conflict(state, info).await;
        return;
    }
    // A pre-Welcome joiner that kept its served chain applies it now.
    let pre_welcome = !info.has_active_member(&local)
        && !state.treekem_groups.read().await.contains_key(group_key);
    if pre_welcome && apply_kept_chain(state, group_key, info, &ata).await {
        return;
    }
    let verified = ata.signer_verified_on(info);
    if !verified {
        if pre_welcome {
            // A joiner verifies a provisional signer only by walking its
            // kept served chain (`apply_kept_chain` above); it applies no
            // link by the ordinary path.
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
        // A non-joiner verifies a provisional signer's promotion path by
        // applying those links through the ordinary path, ungated; until
        // then the ATA has no gate authority (`provisional_tick`).
        let attested_by = ata.fields.attested_by.clone();
        let segment_terminal = ata.fields.segment_terminal_revision;
        {
            let now = Instant::now();
            let mut inner = state.group_recovery.inner.lock().await;
            let subject = inner
                .subjects
                .entry(stable.clone())
                .or_insert_with(|| SubjectState::new(now, info.state_revision));
            subject.provisional = Some((ata, info.state_revision));
            if !subject.view.sticky() {
                subject.view = SubjectView::CatchingUp {
                    attested_by: attested_by.clone(),
                    verified: false,
                    segment_terminal,
                };
            }
        }
        if let Some(raw) = parse_raw(&attested_by) {
            let _ = super::request_treekem_catchup_page(state, group_key, &AgentId(raw)).await;
        }
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
    // The armed record lives in the sidecar only (see `apply_join_carry`);
    // the legacy views get the §4 placeholder.
    if !arm_in_place(state, group_key, info, ata.clone()).await {
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

/// §2 "Verification and signer eligibility", non-joiner: follow a held
/// provisional ATA. While its promotion path is still applying, ask the
/// signer for the next catch-up page whenever the head moves. Once the
/// applied links are the ATA's prefix and the signer is an Active admin
/// on this node's roster, the ATA arms for the rest of its sequence. A
/// path that leaves the sequence, an expired arming window or a revoked
/// signer drops it with `awaiting_attestation {provisional_unverified}`.
async fn provisional_tick(state: &Arc<AppState>, group_key: &str, info: &GroupInfo) {
    let stable = info.stable_group_id().to_string();
    let Some((ata, asked_revision)) = state
        .group_recovery
        .inner
        .lock()
        .await
        .subjects
        .get(&stable)
        .and_then(|subject| subject.provisional.clone())
    else {
        return;
    };
    let window = u64::try_from(s3::ATA_ARM_WINDOW.as_millis()).unwrap_or(u64::MAX);
    let expired = now_ms().saturating_sub(ata.fields.issued_at_ms) > window;
    let signer_revoked = match parse_raw(&ata.fields.attested_by) {
        Some(raw) => agent_revoked(state, &AgentId(raw)).await,
        None => true,
    };
    let armed_elsewhere = armed_admin_ata(state, info).await.is_some();
    let path = if expired || signer_revoked {
        s3::ProvisionalPath::Unverified
    } else {
        s3::provisional_path(&ata, info)
    };
    let signer = parse_raw(&ata.fields.attested_by).map(AgentId);
    match path {
        _ if armed_elsewhere => {
            // Another, verified ATA armed meanwhile: it governs.
            clear_provisional(state, &stable).await;
        }
        s3::ProvisionalPath::Pending => {
            if info.state_revision != asked_revision {
                if let Some(subject) = state
                    .group_recovery
                    .inner
                    .lock()
                    .await
                    .subjects
                    .get_mut(&stable)
                {
                    if let Some((_, asked)) = subject.provisional.as_mut() {
                        *asked = info.state_revision;
                    }
                }
                if let Some(signer) = signer.as_ref() {
                    let _ = super::request_treekem_catchup_page(state, group_key, signer).await;
                }
            }
        }
        s3::ProvisionalPath::Unverified => {
            clear_provisional(state, &stable).await;
            let mut inner = state.group_recovery.inner.lock().await;
            if let Some(subject) = inner.subjects.get_mut(&stable) {
                if !subject.view.sticky() {
                    subject.view = SubjectView::Awaiting {
                        reason: "provisional_unverified".to_string(),
                    };
                }
            }
            drop(inner);
            tracing::info!(group_id = %LogHexId::group(group_key), expired, signer_revoked, "ADR 0109 S3: provisional ATA dropped; its promotion path did not verify");
        }
        s3::ProvisionalPath::Verified => {
            clear_provisional(state, &stable).await;
            // A diverging ATA is recorded before the recorded-conflict
            // stop, so it can narrow the gate (#1533 rc15).
            let diverges = sidecar_snapshot(state, &stable)
                .await
                .and_then(|body| body.active_ata)
                .is_some_and(|active| {
                    active.conflicts_with(&ata) && active.signer_verified_on(info)
                });
            if diverges {
                record_conflict(state, group_key, info, ata).await;
                return;
            }
            if conflict_recorded(state, &stable).await {
                show_conflict(state, info).await;
                return;
            }
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
            if !arm_in_place(state, group_key, info, ata.clone()).await {
                return;
            }
            set_view(
                state,
                &stable,
                info.state_revision,
                SubjectView::CatchingUp {
                    attested_by: ata.fields.attested_by.clone(),
                    verified: true,
                    segment_terminal: ata.fields.segment_terminal_revision,
                },
            )
            .await;
            tracing::info!(group_id = %LogHexId::group(group_key), attested_by = %LogHexId::agent(&ata.fields.attested_by), head = info.state_revision, "ADR 0109 S3: provisional signer verified by its applied promotion path; the ATA arms");
            if let Some(signer) = signer.as_ref() {
                let _ = super::request_treekem_catchup_page(state, group_key, signer).await;
            }
        }
    }
}

/// §4 "Rebuild source" (D147, D119): a pre-Welcome joiner whose damaged
/// sidecar was rebuilt lost its kept served chain and terminal. Before S5,
/// catch-up pages carry membership events only, so a gap that holds a
/// rename or a role change cannot be re-fetched. When such a node is
/// admin-armed and makes no progress for `GATE_STALL`, it enters
/// `readmission_required {cause: local_state_lost}`, with D43's manual
/// remove and re-invite as the exit. Returns whether the node is in that
/// state (it then sends no further request: no answer can help).
async fn local_state_lost(
    state: &AppState,
    group_key: &str,
    info: &GroupInfo,
    now: Instant,
) -> bool {
    let stable = info.stable_group_id();
    let rebuilt_without_chain = sidecar_snapshot(state, stable).await.is_some_and(|body| {
        !body.rebuilt_from.is_empty()
            && body.served_chain.is_empty()
            && body.queued_terminal.is_none()
    });
    if !rebuilt_without_chain {
        return false;
    }
    let pre_welcome = !info.has_active_member(&local_hex(state))
        && !state.treekem_groups.read().await.contains_key(group_key);
    if !pre_welcome || armed_admin_ata(state, info).await.is_none() {
        return false;
    }
    let mut inner = state.group_recovery.inner.lock().await;
    let Some(subject) = inner.subjects.get_mut(stable) else {
        return false;
    };
    if matches!(
        subject.view,
        SubjectView::Readmission {
            cause: "local_state_lost"
        }
    ) {
        return true;
    }
    if info.state_revision != subject.progress_revision {
        subject.progress_revision = info.state_revision;
        subject.progress_at = now;
        return false;
    }
    if now.saturating_duration_since(subject.progress_at) < s3::GATE_STALL {
        return false;
    }
    subject.view = SubjectView::Readmission {
        cause: "local_state_lost",
    };
    drop(inner);
    tracing::warn!(group_id = %LogHexId::group(group_key), "ADR 0109 S3: the rebuilt sidecar lost the served chain and no page supplies the gap; readmission_required (local_state_lost)");
    true
}

async fn clear_provisional(state: &AppState, stable: &str) {
    if let Some(subject) = state
        .group_recovery
        .inner
        .lock()
        .await
        .subjects
        .get_mut(stable)
    {
        subject.provisional = None;
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
    // #1533 review: the central Home mutation fence, before the owner and
    // promoted-admin paths branch. A re-seat credential of an owner-axis
    // group is a device-admission credential: a session bearer never
    // mints one on either path.
    if crate::server::group_access::is_home_or_owner_certified(&info) && !actor.is_durable_owner() {
        return super::mint_refusal_response(
            &id,
            super::MintInviteRefusal::OwnerAxisNoDurableOwner,
        )
        .into_response();
    }
    let stable = info.stable_group_id().to_string();
    // §4 "Timing": the issued authorisation is a sidecar write, so the
    // route signs, stores and mints nothing before ADR 0094's host commit.
    if sidecar_creation_deferred(&state, &stable).await {
        return reseat_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "recovery_deferred",
            serde_json::json!({ "cause": HOST_COMMIT_PENDING }),
        );
    }
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
            .is_some_and(|bases| bases.refs.contains(recovery_ref)),
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
    // One authorisation per `(group, subject)` (§3): the one this call
    // replaces loses its invite durably before the new authorisation is
    // stored, so the replaced pairing can never reach a seal (§3a). The
    // revocation never comes after the store: a failed revocation would
    // then leave the old invite consumable with no paired authorisation,
    // and it would seal as an ordinary add. On the promoted path the
    // revocation is in the same roster write as the new invite, so a
    // signing or encoding failure changes nothing durable. The owner path
    // mints through the shared invite transaction, so it revokes first.
    let replaced = replaced_reseat_secrets(&state, &group_key, &stable, &subject_hex).await;
    if !promoted && !revoke_replaced_reseat_invite(&state, &group_key, &replaced).await {
        return reseat_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_durable",
            serde_json::Value::Null,
        );
    }
    let expiry_secs = s3::RESEAT_AUTHORISATION_LIFETIME.as_secs();
    let minted = if promoted {
        match mint_reseat_invite(&state, &group_key, subject, expiry_secs, &replaced).await {
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
        reason_hash: s3::reason_hash(request.reason.trim()),
        expires_at_ms,
    };
    let authorisation = match ReseatAuthorisation::sign(fields, keypair) {
        Ok(authorisation) => authorisation,
        Err(error) => {
            revoke_unpaired_reseat_invite(&state, &group_key, &subject_hex, &invite).await;
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
        // #1648: the store failed, so no authorisation pairs with the
        // minted invite. Revoke it before the route answers. This is the
        // mirror of the pre-mint rule above: there the replaced invite
        // must not outlive the store, here the new one must not outlive
        // its failed store.
        revoke_unpaired_reseat_invite(&state, &group_key, &subject_hex, &invite).await;
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
    let push_guard = Guard::Reseat(authorisation.digest());
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
            push_guard,
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
            let now = now_ms();
            body.issued_reseats
                .iter()
                .filter(|issued| issued.authorisation.fields.expires_at_ms > now)
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

/// How long an expired issued re-seat stays in the sidecar. An invite is
/// consumable to the end of its expiry second, up to 999 ms after its
/// authorisation expires; the entry must outlive that, so the seal can
/// tell a re-seat invite that lost its pairing from an ordinary invite.
const RESEAT_SEAL_RETENTION_MS: u64 = 60_000;

/// The issued re-seat whose invite secret this `MemberJoined` redeems, for
/// this subject, expired or not (§3a: the issuing admin applies checks 1
/// and 2 again when the join request arrives). The caller checks expiry.
async fn recorded_reseat_for_secret(
    state: &AppState,
    stable_group_id: &str,
    subject_hex: &str,
    invite_secret: &str,
) -> Option<IssuedReseatV1> {
    let hash = s3::invite_secret_hash(invite_secret);
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
            let fields = &issued.authorisation.fields;
            fields.subject.eq_ignore_ascii_case(subject_hex) && fields.invite_secret_hash == hash
        })
        .cloned()
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
    // #1533 rc22 (ZCode MAJOR-2): a re-seat invite whose authorisation
    // expired before the seal is still a re-seat invite. It seals nothing;
    // it never falls through to an ordinary add with no mandate. A
    // replaced authorisation's invite is revoked by
    // [`reseat_group_member`] (owner path) or in [`mint_reseat_invite`]'s
    // roster write (promoted path), so it never reaches the seal.
    let Some(issued) =
        recorded_reseat_for_secret(state, parent.stable_group_id(), subject_hex, invite_secret)
            .await
    else {
        return ReseatSeal::NotReseat;
    };
    if issued.authorisation.fields.expires_at_ms <= now_ms() {
        return ReseatSeal::Refused("reseat_invite_unpaired");
    }
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
    member_joined_recovery: Option<&super::NamedGroupMetadataEvent>,
    treekem_commit_b64: Option<&str>,
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
            || mandate.verify_signature(&commit.signer_public_key).is_err()
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
        // #1578 rc11 (audit): the join's key-only marker row is not a
        // seat — the subject reads as unseated, exactly main's roster.
        let seated_role = next
            .members_v2
            .get(subject_hex)
            .filter(|_| !next.join_seat_key_marker_only(subject_hex))
            .map(|seat| seat.role);
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
    // #1578 rc11 (audit): the join's key-only marker row is not a seat
    // — the subject reads as unseated (Guest), exactly main's roster.
    let seated_role = next
        .members_v2
        .get(subject_hex)
        .filter(|_| !next.join_seat_key_marker_only(subject_hex))
        .map_or(x0x::groups::GroupRole::Guest, |seat| seat.role);
    // §3a check 8 (#1680, Engineer ruling 30 Oct 2026: fail closed): the
    // KeyPackage must verify against the subject's agent key, exactly as
    // an ordinary join's does, and the evidence is the subject-signed
    // `MemberJoined` the re-seat event itself carries
    // (`member_joined_recovery`) — a receiver without it refuses the
    // re-seat, as the Accepted ADR reads. The root rule still refuses a
    // packageless re-seat on the TreeKEM plane (every re-seat there has a
    // package). The receiver's own cached record for the same package
    // must not contradict the carried one (a poisoned persisted cache).
    let key_package_bound_to_subject = carried_member_joined_binds_package(
        member_joined_recovery,
        subject_hex,
        certificate,
        &mandate.fields.key_package_hash,
    ) && held_key_package_bound_to_subject(
        state,
        parent,
        subject_hex,
        &mandate.fields.key_package_hash,
        certificate,
    )
    .await;
    let check = x0x::groups::recovery::ReseatMandateCheck {
        parent,
        commit,
        subject: subject_hex,
        key_package_hash: Some(key_package_hash.unwrap_or_default()),
        key_package_bound_to_subject,
        treekem_plane: parent.secure_plane == x0x::mls::SecureGroupPlane::TreeKem,
        epoch: Some(epoch.unwrap_or_default()),
        seated_role,
        certificate_digest: digest.as_deref(),
        certificate_valid,
        subject_revoked,
    };
    x0x::groups::recovery::verify_reseat_mandate(mandate, &check)
        .map_err(|cause| cause.as_str())?;
    // Check 8's commit half (#1680, round-1 review finding 3): when the
    // event carries the TreeKEM commit, the leaf it adds must be the
    // bound package — the mandate's hash binding alone does not stop a
    // commit that adds a different leaf. It runs after the root rule, so
    // an earlier failed check still names its own §3a cause.
    if !mandate.fields.key_package_hash.is_empty()
        && treekem_commit_b64.is_some_and(|commit_b64| {
            !treekem_commit_adds_exactly_the_bound_package(
                commit_b64,
                &mandate.fields.key_package_hash,
            )
        })
    {
        return Err("binding_mismatch");
    }
    Ok(())
}

/// §3a check 8 (#1680, Engineer ruling 30 Oct 2026): whether the
/// `MemberJoined` record carried inside the re-seat `MemberAdded`
/// (`member_joined_recovery`) binds the bound KeyPackage to the subject.
/// The record must be the subject's own, not authority-only, and must
/// pass exactly what an ordinary join's package evidence passes: the
/// member self-signature verifies (an authority-only record has no
/// member half and cannot), its public key is the agent key the
/// subject's certificate names, and the package hashes to the mandate's
/// bound hash. A missing, authority-only, foreign-signed or mismatched
/// record fails check 8 — fail closed, per the ruling (PR #1728 comment
/// 6528069544). A re-seat that binds no package (an empty hash) has no
/// check-8 evidence to carry.
fn carried_member_joined_binds_package(
    record: Option<&super::NamedGroupMetadataEvent>,
    subject_hex: &str,
    certificate: Option<&x0x::identity::AgentCertificate>,
    bound_hash: &str,
) -> bool {
    use base64::Engine as _;

    if bound_hash.is_empty() {
        return true;
    }
    let Some(record) = record else {
        return false;
    };
    let super::NamedGroupMetadataEvent::MemberJoined {
        member_agent_id,
        member_public_key_b64,
        treekem_key_package_b64: Some(package),
        ..
    } = record
    else {
        return false;
    };
    member_agent_id.eq_ignore_ascii_case(subject_hex)
        && super::verify_member_joined_key_package_event(record)
        && blake3::hash(package.as_bytes()).to_hex().as_str() == bound_hash
        && certificate.is_some_and(|cert| {
            super::BASE64
                .decode(member_public_key_b64.as_str())
                .is_ok_and(|key| key == cert.agent_public_key())
        })
}

/// §3a check 8's commit half (#1680, round-1 review finding 3): a
/// re-seat's TreeKEM commit must add exactly the bound KeyPackage —
/// every added leaf's package hashes to the mandate's bound hash, and a
/// commit that adds nothing, does not decode, or adds any other package
/// is not the blessed re-seat.
fn treekem_commit_adds_exactly_the_bound_package(commit_b64: &str, bound_hash: &str) -> bool {
    use base64::Engine as _;

    let Ok(bytes) = super::BASE64.decode(commit_b64) else {
        return false;
    };
    match crate::mls::treekem::commit_added_key_package_hashes(&bytes) {
        Ok(hashes) => !hashes.is_empty() && hashes.iter().all(|hash| hash == bound_hash),
        Err(_) => false,
    }
}

/// §3a check 8 (#1680): the receiver's own cached record must not
/// contradict the carried subject-signed evidence. The cache keys its
/// member half lower-case, as the ingress does:
///
/// - a record for a DIFFERENT package is an older incarnation of the
///   seat, not evidence about this re-seat's package, so it decides
///   nothing;
/// - an AUTHORITY-ONLY record for the same package (the direct-add
///   shape, round-1 review finding 2) carries no member binding at all,
///   so it decides nothing either — the carried record is the evidence;
/// - a MEMBER-SIGNED record for the SAME package must verify: its
///   self-signature checks and its member key is the agent key the
///   owner's certificate names for the subject. The persisted cache is
///   restored verbatim at startup, so a record that fails here is a
///   poisoned cache and refuses the re-seat.
async fn held_key_package_bound_to_subject(
    state: &AppState,
    parent: &GroupInfo,
    subject_hex: &str,
    bound_hash: &str,
    certificate: Option<&x0x::identity::AgentCertificate>,
) -> bool {
    if bound_hash.is_empty() {
        return true;
    }
    // The cache keys its member half lower-case, as the ingress does.
    let member_key = subject_hex.to_ascii_lowercase();
    for group_key in [
        parent.stable_group_id().to_string(),
        parent.mls_group_id.clone(),
    ] {
        let Some(record) = state
            .treekem_member_key_packages
            .get(&super::join_result_key(&group_key, &member_key))
            .await
        else {
            continue;
        };
        let super::NamedGroupMetadataEvent::MemberJoined {
            member_public_key_b64,
            treekem_key_package_b64: Some(package),
            ..
        } = &record
        else {
            continue;
        };
        if blake3::hash(package.as_bytes()).to_hex().as_str() != bound_hash {
            continue;
        }
        // Authority-only (the direct-add shape): no member half, so no
        // member binding to check — the carried record decides (round-1
        // review finding 2: this must not refuse an honest re-seat).
        if member_public_key_b64.is_empty() {
            continue;
        }
        use base64::Engine as _;
        return super::verify_member_joined_key_package_event(&record)
            && certificate.is_some_and(|cert| {
                super::BASE64
                    .decode(member_public_key_b64.as_str())
                    .is_ok_and(|key| key == cert.agent_public_key())
            });
    }
    true
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

/// §3 "one per `(group, subject)`": the unconsumed invite secrets that
/// the issued re-seat for `subject_hex` pairs with, which the route
/// revokes before, or in the same roster write as, the replacement, so a join with one fails
/// invite consumption before any seal.
async fn replaced_reseat_secrets(
    state: &AppState,
    group_key: &str,
    stable_group_id: &str,
    subject_hex: &str,
) -> Vec<String> {
    let hashes: Vec<String> = sidecar_snapshot(state, stable_group_id)
        .await
        .map(|body| {
            body.issued_reseats
                .iter()
                .filter(|issued| {
                    issued
                        .authorisation
                        .fields
                        .subject
                        .eq_ignore_ascii_case(subject_hex)
                })
                .map(|issued| issued.authorisation.fields.invite_secret_hash.clone())
                .collect()
        })
        .unwrap_or_default();
    if hashes.is_empty() {
        return Vec::new();
    }
    state
        .named_groups
        .read()
        .await
        .get(group_key)
        .map(|info| {
            info.issued_invites
                .iter()
                .filter(|(secret, record)| {
                    record.consumed_by.is_none() && hashes.contains(&s3::invite_secret_hash(secret))
                })
                .map(|(secret, _)| secret.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Drop `secrets` from both issued-invite maps of `info`.
fn drop_issued_invites(info: &mut GroupInfo, secrets: &[String]) {
    for secret in secrets {
        info.issued_invites.remove(secret);
        info.issued_invite_secrets.remove(secret);
    }
}

/// Remove `secrets` from the group's issued invites in a durable roster
/// write. Returns whether the roster is durable (or nothing was to
/// revoke). The caller holds the group's membership lock.
async fn revoke_replaced_reseat_invite(
    state: &AppState,
    group_key: &str,
    secrets: &[String],
) -> bool {
    if secrets.is_empty() {
        return true;
    }
    let Some(mut next) = state.named_groups.read().await.get(group_key).cloned() else {
        return true;
    };
    drop_issued_invites(&mut next, secrets);
    matches!(
        super::persist_named_group_info(state, group_key, next).await,
        Ok(super::AtomicWriteOutcome::Durable)
    )
}

/// #1648: between the durable mint and the sidecar store the invite is
/// live, but no recorded authorisation pairs with it. A failure in that
/// window — the authorisation signature, or a sidecar store that is not
/// durable — revokes the minted invite before the route answers, so no
/// orphan invite stays consumable. The revocation is a durable roster
/// write under the caller-held membership lock. A revocation that is
/// itself not durable is logged; the 1-hour invite expiry stays the
/// backstop for that double failure. The caller holds the group's
/// membership lock.
async fn revoke_unpaired_reseat_invite(
    state: &AppState,
    group_key: &str,
    subject_hex: &str,
    invite: &x0x::groups::invite::SignedInvite,
) {
    if !revoke_replaced_reseat_invite(
        state,
        group_key,
        std::slice::from_ref(&invite.invite_secret),
    )
    .await
    {
        tracing::error!(
            group_id = %LogHexId::group(group_key),
            subject = %LogHexId::agent(subject_hex),
            "ADR 0109 S3: a failed authorisation leaves its minted invite live; the revocation is not durable"
        );
    }
}

/// Mint a re-seat invite for the promoted-admin path (§3a): an InviteV4
/// signed by this admin's agent key alone, with no owner countersignature,
/// addressed to the subject and recorded as an ordinary issued invite. Its
/// re-seat scope is the paired authorisation: only the named subject, at
/// this admin, with the matching unconsumed authorisation, can redeem it.
/// The same roster write revokes the `replaced` invite secrets, so an
/// error before it changes nothing durable.
async fn mint_reseat_invite(
    state: &AppState,
    group_key: &str,
    subject: AgentId,
    expiry_secs: u64,
    replaced: &[String],
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
    drop_issued_invites(&mut next, replaced);
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

/// The `cause` that `authorisation_refused {cause}` reports (§3, row
/// H-S3-d3): `signature`, `signer`, `subject`, `basis`,
/// `base_seats_subject` or `expired`. The internal checks give finer
/// causes; each signer check maps to `signer`, the subject check to
/// `subject` and each basis check to `basis`. Any other cause is reported
/// as it is. The log keeps the fine cause.
fn authorisation_refused_cause(check: &str) -> &str {
    match check {
        "signer_not_inviter"
        | "signer_not_admin_on_base"
        | "signer_not_admin_locally"
        | "signer_revoked" => "signer",
        "subject_mismatch" => "subject",
        "basis_not_live" | "basis_unknown" => "basis",
        "record_key_divergent" => "group_mismatch",
        other => other,
    }
}

async fn refuse_authorisation(state: &AppState, stable: &str, revision: u64, check: &str) {
    let cause = authorisation_refused_cause(check);
    tracing::info!(group_id = %LogHexId::group(stable), cause, check, "ADR 0109 S3: authorisation_refused");
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

/// §3 subject checks anchored in this node's own verified record
/// (#1533 review, Codex P1; Engineer ruling of 22 Oct). The invite's base
/// roster is the signer's own claim, so it is never the authority by
/// itself:
/// - the signer is an Active admin (or higher) on this node's own head.
///   Each role change in `members_v2` came through a signed commit that
///   this node verified as it applied it, so a promotion it applied counts
///   and a promotion it never saw does not. With no such seat the subject
///   refuses `signer_not_admin_locally` (fail closed);
/// - a `Removal` basis is not after the invite base it is paired with, and
///   a commit this node holds at that revision and hash must be its own
///   removal on its own chain ([`s3::removal_commit_on_chain`]); otherwise
///   `basis_unknown`. A removal this node never saw (it is forked or
///   removed) stays the signer's claim, under the signer's local authority.
fn check_reseat_authority(
    info: &GroupInfo,
    authorisation: &ReseatAuthorisation,
    local: &str,
) -> Result<(), &'static str> {
    let fields = &authorisation.fields;
    if !s3::signer_is_active_admin(info, &fields.signer) {
        return Err("signer_not_admin_locally");
    }
    if let ReseatBasis::Removal {
        revision,
        state_hash,
    } = &fields.basis
    {
        if *revision > fields.invite_base_revision {
            return Err("basis_unknown");
        }
        let held = info.commit_log.iter().any(|entry| {
            entry.commit.revision == *revision && entry.commit.state_hash == *state_hash
        });
        if held && !s3::removal_commit_on_chain(info, local, *revision, state_hash) {
            return Err("basis_unknown");
        }
    }
    Ok(())
}

/// #1689 review: the live record's map key, its `mls_group_id` and the
/// re-seat invite's `group_id` must be one key. The staging slot opens at
/// the map key, the staged join seats the record at the invite's
/// `group_id`, and the promote and the discard close the slot by one key.
/// A legacy record keyed apart from its `mls_group_id` (a pre-pin genesis
/// id) would leave a slot open under the other key, so it is refused
/// (`record_key_divergent`, cause `group_mismatch`) before anything is
/// journalled or moved.
fn check_reseat_keys(
    group_key: &str,
    info: &GroupInfo,
    invite: &x0x::groups::invite::SignedInvite,
) -> Result<(), &'static str> {
    if group_key == info.mls_group_id && invite.group_id == group_key {
        Ok(())
    } else {
        Err("record_key_divergent")
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
        return Err("reseat_invite_unpaired");
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
    // No Home gate here: a manual re-seat is not Home activation (§4). The
    // open journal keeps the original in every legacy file
    // ([`reseat_overlay`]), and a Home-policy staged join pins its owner.
    let stable = info.stable_group_id().to_string();
    if sidecar_snapshot(state, &stable)
        .await
        .is_some_and(|body| body.reseat_journal.is_some())
    {
        return;
    }
    let refs = live_refs(state, &info).await;
    // The authorisation carries no key (§3): it is checked under the
    // paired invite's inline inviter key, which must hash to the signer.
    let Ok(invite) = x0x::groups::invite::SignedInvite::from_link(&invite_link) else {
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, "invite_malformed").await;
        return;
    };
    let inviter_key = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(invite.inviter_public_key_b64.as_bytes())
            .map(hex::encode)
            .unwrap_or_default()
    };
    if let Err(cause) = authorisation.check_for_subject(
        &stable,
        &local,
        &refs,
        now_ms(),
        (&invite.inviter, &inviter_key),
    ) {
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, cause).await;
        return;
    }
    let signer_revoked = match parse_raw(&authorisation.fields.signer) {
        Some(raw) => agent_revoked(state, &AgentId(raw)).await,
        None => true,
    };
    let anchored = if signer_revoked {
        Err("signer_revoked")
    } else {
        check_reseat_authority(&info, &authorisation, &local)
    };
    if let Err(cause) = anchored {
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, cause).await;
        return;
    }
    if let Err(cause) = check_reseat_invite(&invite, &authorisation, &stable, &local)
        .and_then(|()| check_reseat_keys(group_key, &info, &invite))
    {
        drop(membership_guard);
        refuse_authorisation(state, &stable, info.state_revision, cause).await;
        return;
    }
    // §4 "Timing": the journal is the first sidecar write; it waits for
    // ADR 0094's host commit. The authorisation is offered again.
    if defer_for_host_commit(state, &stable, info.state_revision).await {
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
        phase: ReseatPhase::Prepared,
        live_key: group_key.to_string(),
        live_record,
        live_tree,
        started_at_ms: now_ms(),
    };
    // While this process prepares, the worker leaves the `Prepared`
    // journal alone; after a restart (no entry here) it rolls it back.
    state
        .group_recovery
        .inner
        .lock()
        .await
        .staging_live
        .insert(stable.clone());
    let digest = journal.record_digest;
    if let Err(why) = prepare_reseat(state, group_key, &info, journal).await {
        drop(membership_guard);
        // The journal (when it became durable) holds the original record
        // and tree. The rollback closes it only once the original is
        // durable again; until then the worker retries it.
        rollback_reseat(state, &stable, digest, why).await;
        state
            .group_recovery
            .inner
            .lock()
            .await
            .staging_live
            .remove(&stable);
        refuse_authorisation(state, &stable, info.state_revision, why).await;
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
    // §3 step 2 (#1699): the staged join, and every step that it spawns,
    // runs in the staging slot. The live record stays contained.
    let response = state
        .reseat_stagings
        .run_in_staging_of(
            group_key,
            super::join_group_via_invite_inner(Arc::clone(state), request, true),
        )
        .await
        .into_response();
    if !response.status().is_success() {
        let status = response.status();
        tracing::warn!(group_id = %LogHexId::group(group_key), %status, "ADR 0109 S3: the staged join was refused; restoring the live record");
        rollback_reseat(state, &stable, digest, &format!("join_{}", status.as_u16())).await;
    } else {
        // The join can return with the record already Active with keys:
        // swap now rather than at the next worker tick.
        swap_now_if_seated(state, &stable).await;
    }
}

/// §3 steps 1 and 2 under the membership lock: write the journal
/// (`Prepared`), open the staging slot, then mark the journal `Staging`. Each step is durable before the next starts.
/// On `Err` the caller rolls back with [`rollback_reseat`], which keeps the
/// journal until the original record is durable again.
async fn prepare_reseat(
    state: &Arc<AppState>,
    group_key: &str,
    info: &GroupInfo,
    journal: ReseatJournalV1,
) -> Result<(), &'static str> {
    let stable = info.stable_group_id().to_string();
    if !update_sidecar(state, &stable, move |body| {
        body.reseat_journal = Some(journal);
    })
    .await
    {
        return Err("journal_not_durable");
    }
    open_staging(state, group_key, info).await;
    let mut marked = false;
    let marked_ref = &mut marked;
    let durable = update_sidecar(state, &stable, move |body| {
        if let Some(journal) = body.reseat_journal.as_mut() {
            journal.phase = ReseatPhase::Staging;
            *marked_ref = true;
        }
    })
    .await;
    if durable && marked {
        Ok(())
    } else {
        Err("journal_not_durable")
    }
}

/// §3 step 2 (#1699): open an empty staging slot for the staged join. The
/// contained original stays in the live map, with its tree, marker, gate
/// and membership, until the swap; the serving paths, the API and the
/// probes keep seeing it. The staged join runs in the scope
/// ([`ReseatStagings`](crate::server::reseat_scope::ReseatStagings)), so
/// it starts from no local record. The open journal keeps the original in
/// every legacy file ([`reseat_overlay`]) and its tree in the snapshot
/// file (#1567, `reseat_snapshot_cover`).
async fn open_staging(state: &Arc<AppState>, group_key: &str, info: &GroupInfo) {
    let stable = info.stable_group_id().to_string();
    discard_staging(state, group_key, &stable).await;
    let aliases = super::join_artifact_group_aliases(state, group_key).await;
    super::retire_local_group_join_artifacts(state, &aliases).await;
    state.group_card_cache.write().await.remove(group_key);
    let mut cache_aliases = aliases;
    cache_aliases.insert(group_key.to_string());
    cache_aliases.insert(stable.clone());
    let _ = super::prune_treekem_cache_groups(state, &cache_aliases, "adr0109_reseat").await;
    state.reseat_stagings.open(group_key, &stable);
}

/// Close the re-seat staging of `key` and empty its slot in the three
/// group maps. A task of the staged join that still runs then uses the
/// live map. Returns whether a staging was open.
async fn discard_staging(state: &AppState, key: &str, stable: &str) -> bool {
    let closed = state.reseat_stagings.close(key);
    {
        // #1689 review: `refresh_group_rosters_for_gossip` reads the slot
        // under this lock. Emptying it under the same lock narrows the race
        // with a rollback but does not close it: a refresh that read the
        // slot before this point can still publish the abandoned staged
        // roster once, and the next refresh replaces it.
        let _persistence_guard = state.named_groups_persistence_lock.lock().await;
        state
            .named_groups
            .staging_write()
            .await
            .retain(|staged_key, info| staged_key != key && info.stable_group_id() != stable);
    }
    state.treekem_groups.staging_write().await.remove(key);
    state.mls_groups.staging_write().await.remove(key);
    if closed {
        // The staged stub's key is the original's: it is not a pending
        // join stub of the live map.
        state
            .pending_join_stubs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(key);
    }
    closed
}

/// §3 step 3 (#1699): after the staged pair is durable, its tree and MLS
/// state replace the original's in the live map. `named` also copies the
/// staged record (the tree write put it in the live map already when the
/// group has a tree). The slot keeps its copy, so a retried swap finds the
/// pair again; it is emptied when the journal closes ([`swap_if_seated`]).
async fn promote_staging(state: &AppState, key: &str, named: bool) {
    if named {
        let staged = state.named_groups.staging_read().await.get(key).cloned();
        if let Some(staged) = staged {
            state
                .named_groups
                .live_write()
                .await
                .insert(key.to_string(), staged);
        }
    }
    let tree = state.treekem_groups.staging_read().await.get(key).cloned();
    if let Some(tree) = tree {
        state
            .treekem_groups
            .live_write()
            .await
            .insert(key.to_string(), tree);
    }
    let mls = state.mls_groups.staging_write().await.remove(key);
    if let Some(mls) = mls {
        state
            .mls_groups
            .live_write()
            .await
            .insert(key.to_string(), mls);
    }
}

/// Put the journalled original record back durably, then close the journal;
/// the node shows `reseat_required {reseat_failed}` (§3 step 4). The
/// journal stays open, and the worker retries, until the original record
/// is durable again: only a durable rollback (or a durable swap) closes it.
///
/// - The staging slot is emptied and closed first (#1699).
/// - `Prepared`, or a live record that is the journalled original: the
///   original never left the live map. It is written again so that it is
///   durable, with its tree untouched.
/// - otherwise, or with no record under the key: the record and its tree
///   are restored from the journal.
///
/// `expected` is the `record_digest` of the journal that the caller
/// decided to roll back. The journal is read again under the membership
/// lock, which the swap also holds ([`swap_if_seated`]): when the swap
/// closed that journal first, or another journal is open, nothing changes.
/// The journal closes under the same lock.
async fn rollback_reseat(state: &Arc<AppState>, stable: &str, expected: [u8; 32], why: &str) {
    let lock = super::group_membership_lock(state, stable).await;
    let membership_guard = lock.lock().await;
    let Some(journal) = sidecar_snapshot(state, stable)
        .await
        .and_then(|body| body.reseat_journal)
        .filter(|journal| journal.record_digest == expected)
    else {
        return;
    };
    let Ok(record) = serde_json::from_slice::<GroupInfo>(&journal.live_record) else {
        tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the journalled live record does not decode; the journal stays");
        return;
    };
    let key = journal.live_key.clone();
    // #1699: the staged record goes; the original never left the live map
    // in this process. After a restart (no staging) the live record is the
    // original too, unless a failed swap's journals replayed the staged
    // pair, which the journal copy then replaces.
    discard_staging(state, &key, stable).await;
    let still_live = state
        .named_groups
        .live_read()
        .await
        .get(&key)
        .cloned()
        .filter(|live| {
            journal.phase == ReseatPhase::Prepared || is_journalled_original(live, &journal)
        });
    let (restored, revision) = match still_live {
        Some(original) => {
            let revision = original.state_revision;
            let durable = matches!(
                super::persist_named_group_info(state, &key, original).await,
                Ok(super::AtomicWriteOutcome::Durable)
            );
            (durable, revision)
        }
        None => (
            restore_record_from_journal(state, stable, &key, &record, &journal).await,
            record.state_revision,
        ),
    };
    if !restored {
        tracing::warn!(group_id = %LogHexId::group(stable), why, "ADR 0109 S3: the re-seat rollback is not durable yet; the journal stays and the worker retries");
        return;
    }
    let closed = update_sidecar(state, stable, |body| {
        if body
            .reseat_journal
            .as_ref()
            .is_some_and(|open| open.record_digest == expected)
        {
            body.reseat_journal = None;
        }
    })
    .await;
    drop(membership_guard);
    if !closed {
        // The original is durable; closing the journal is retried.
        return;
    }
    let refs = state
        .named_groups
        .read()
        .await
        .get(&key)
        .map(RecoveryRef::live_refs)
        .unwrap_or_default();
    let now = Instant::now();
    let mut inner = state.group_recovery.inner.lock().await;
    inner.staging_live.remove(stable);
    let subject = inner
        .subjects
        .entry(stable.to_string())
        .or_insert_with(|| SubjectState::new(now, revision));
    subject.view = SubjectView::Reseat {
        cause: "reseat_failed",
        recovery_ref: refs.into_iter().next(),
    };
    subject.last_refusal = Some(why.to_string());
    tracing::warn!(group_id = %LogHexId::group(stable), why, "ADR 0109 S3: re-seat failed; the contained live record is restored");
}

/// Remove any staging stub under `key`, then write the journalled record
/// and its tree back in one TreeKEM persist transaction (or the record
/// alone when it had no tree). Returns whether that write is durable.
async fn restore_record_from_journal(
    state: &AppState,
    stable: &str,
    key: &str,
    record: &GroupInfo,
    journal: &ReseatJournalV1,
) -> bool {
    let stub_key = key.to_string();
    let _ = super::persist_named_groups_mutation(state, move |groups| {
        groups.remove(&stub_key).is_some()
    })
    .await;
    state.treekem_groups.write().await.remove(key);
    match journal.live_tree.as_deref() {
        Some(snapshot) => {
            match super::restore_local_treekem_group_from_snapshot(state, record, snapshot) {
                Ok(tree) => {
                    let persisted = super::persist_treekem_and_named_groups_atomic_with_info(
                        state,
                        key,
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
                            .insert(key.to_string(), Arc::new(tokio::sync::Mutex::new(tree)));
                    }
                    persisted
                }
                Err(error) => {
                    tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: cannot restore the journalled tree: {error}");
                    false
                }
            }
        }
        // The key is absent (an older binary moved the original aside, or a
        // replayed staged pair was removed above): insert, since
        // `persist_named_group_info` only replaces.
        None => {
            let restore_key = key.to_string();
            let restored = record.clone();
            matches!(
                super::persist_named_groups_mutation(state, move |groups| {
                    groups.insert(restore_key, restored);
                    true
                })
                .await,
                Ok(super::AtomicWriteOutcome::Durable)
            )
        }
    }
}

/// Where the swap finds the staged pair (#1699).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagedSource {
    /// The staging slot of the staged join in this process.
    Staging,
    /// The live map: after a restart the seal journals of a `Swapping`
    /// journal replayed the staged pair there (#1645), and the swap
    /// retries forward.
    Replayed,
}

impl StagedSource {
    async fn of<'a, V>(
        self,
        map: &'a crate::server::reseat_scope::ScopedGroupMap<V>,
    ) -> tokio::sync::RwLockReadGuard<'a, HashMap<String, V>> {
        match self {
            Self::Staging => map.staging_read().await,
            Self::Replayed => map.live_read().await,
        }
    }
}

/// The staged record whose stable id is `stable`, with its map key and
/// where it is (#1699): the staging slot while a staging is open, else a
/// live record of a `Swapping` journal that is not the original.
async fn staged_record_for(
    state: &AppState,
    stable: &str,
    journal: &ReseatJournalV1,
) -> Option<(String, GroupInfo, StagedSource)> {
    let find = |groups: &HashMap<String, GroupInfo>| {
        groups
            .iter()
            .find(|(_, info)| info.stable_group_id() == stable)
            .map(|(key, info)| (key.clone(), info.clone()))
    };
    if state.reseat_stagings.scope_for(&journal.live_key).is_some() {
        let groups = state.named_groups.staging_read().await;
        return find(&groups).map(|(key, info)| (key, info, StagedSource::Staging));
    }
    if journal.phase != ReseatPhase::Swapping {
        return None;
    }
    let groups = state.named_groups.live_read().await;
    find(&groups).map(|(key, info)| (key, info, StagedSource::Replayed))
}

/// The live record whose stable id is `stable`, with its map key.
async fn live_record_for(state: &AppState, stable: &str) -> Option<(String, GroupInfo)> {
    let groups = state.named_groups.live_read().await;
    groups
        .iter()
        .find(|(_, info)| info.stable_group_id() == stable)
        .map(|(key, info)| (key.clone(), info.clone()))
}

/// §3 step 3: when the staged record is the bound result of this journal
/// ([`ReseatJournalV1::staged_result_ready`]), swap it in. The journal
/// closes and the old record is retired (cause `reseat`) in one sidecar
/// write, with the S3 state of the old record (its ATA, served chain,
/// queued terminal and any attestation conflict), and the subject's
/// `reseat_in_progress` view is cleared with it. Returns whether the
/// record is swapped (by this call or an earlier one, or its durable write
/// failed and the next tick retries).
///
/// A `Prepared` journal, or a record that is still the journalled original
/// (the staging slot holds no staged record, #1699), never swaps: the
/// original forked record can show this node Active with a tree.
///
/// The worker tick calls this, and so do the staged join's return and the
/// `recovery` object read, so a reader never sees `reseat_in_progress`
/// for a record that is already Active.
///
/// #1533 review: the whole swap runs under the group membership lock,
/// which [`rollback_reseat`] also holds, and it reads the journal and the
/// live record under that lock. A rollback that restored the original
/// therefore comes before the readiness check (which then sees the
/// original and does not swap) or after the swap closed the journal
/// (which then makes the rollback a no-op). The swap never clears the
/// original's marker. Returns `true` when no journal is open.
async fn swap_if_seated(state: &AppState, stable: &str) -> bool {
    let lock = super::group_membership_lock(state, stable).await;
    let _membership_guard = lock.lock().await;
    // #1645: a failed swap's files go back first. Until then nothing else
    // of the re-seat runs (its rollback writes the roster too).
    if !resolve_failed_swap(state, stable).await {
        return true;
    }
    let Some(journal) = sidecar_snapshot(state, stable)
        .await
        .and_then(|body| body.reseat_journal)
    else {
        return true;
    };
    let journal = &journal;
    let staged = staged_record_for(state, stable, journal).await;
    let local = local_hex(state);
    let seated = match staged.as_ref() {
        Some((key, info, source)) if !is_journalled_original(info, journal) => {
            let has_tree = source.of(&state.treekem_groups).await.contains_key(key);
            journal
                .staged_result_ready(info, &local, has_tree)
                .then(|| (key.clone(), *source))
        }
        _ => None,
    };
    let Some((key, source)) = seated else {
        return false;
    };
    // The slot is opened at the original's key ([`open_staging`]), and the
    // promote and discard below close it by that key. [`consume_reseat`]
    // refuses a record whose keys differ, so this is a backstop that
    // should not run: a staged record at another key is never promoted,
    // and the journal stays open and rolls back.
    if key != journal.live_key {
        tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the staged key is not the journalled live key (unexpected); the swap is refused");
        return false;
    }
    let expected = journal.record_digest;
    // §3 step 3 (#1533 review): `Swapping` lifts the legacy overlay and the
    // marker hold, then one durable roster write puts the staged record in
    // the legacy files without the original's marker before the journal
    // closes. A crash before that write loads the original, which rolls
    // back.
    if !swap_staged_tree(state, stable, journal, &key, source).await {
        return true;
    }
    if !lift_staging_marker(state, stable, journal).await {
        tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the swapped-in record is not durable yet; it keeps the original's marker and the swap is retried");
        return true;
    }
    let retired = RetiredRecordV1 {
        cause: "reseat".to_string(),
        retired_at_ms: now_ms(),
        record: journal.live_record.clone(),
    };
    let mut swapped = false;
    let swapped_ref = &mut swapped;
    if update_sidecar(state, stable, move |body| {
        let same = body
            .reseat_journal
            .as_ref()
            .is_some_and(|open| open.record_digest == expected);
        if same {
            body.reseat_journal = None;
            body.active_ata = None;
            body.attestation_conflict = None;
            body.served_chain.clear();
            body.queued_terminal = None;
            body.retire(retired);
            *swapped_ref = true;
        }
    })
    .await
    {
        // The journal is closed: the staged pair is the live one now.
        discard_staging(state, &key, stable).await;
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

/// #1645: the original pair's files from before the swap's tree write,
/// which a failed write puts back. Only the swap that made the `Swapping`
/// mark reads them: memory never advances the original's tree, so they
/// cannot rewind a ratchet.
struct SwapBefore {
    cover: super::ReseatSnapshotCover,
    rosters: super::RosterStoresBefore,
}

/// #1645: a failed swap whose files may be mixed
/// ([`S3Inner::failed_swaps`]). No other roster write runs meanwhile.
/// At most one key is pinned: a pin is set only in [`swap_staged_tree`],
/// under `named_groups_persistence_lock` and after its check that no
/// other key is pinned, so two pins can never wait on each other.
enum FailedSwap {
    /// The swap made the `Swapping` mark. Each tick puts `before` (the
    /// original pair) back, then ends the swap.
    Rollback {
        stable: String,
        expected: [u8; 32],
        before: SwapBefore,
    },
    /// A retry of a `Swapping` journal (round 4 review). Its transaction
    /// journals replay the staged pair that `Swapping` names, with the
    /// tree that memory holds now, so nothing is put back: files read
    /// before the retry can be a mixed set or an older ratchet. Each tick
    /// retries the tree write forward, and only a write past its commit
    /// point that leaves the staged pair durable ends the refusal.
    Forward,
}

/// #1645 (round 4 audit): refuse a whole-roster write while a failed
/// re-seat swap's files may be mixed, except the tree write of that swap
/// (`allow`, its key), which retries forward. After a tree write that
/// failed past its commit point, only the transaction journals make the
/// files a matching pair again (a restart replays them). A later roster
/// write would put the staged record beside the original's tree, and its
/// newer revision makes the startup replay drop the journals as stale.
/// The refusal ends when the staged pair is durable or the original files
/// are all back.
pub(super) async fn refuse_roster_write_during_failed_swap(
    state: &AppState,
    allow: Option<&str>,
) -> std::io::Result<()> {
    let inner = state.group_recovery.inner.lock().await;
    match inner
        .failed_swaps
        .keys()
        .find(|key| Some(key.as_str()) != allow)
    {
        Some(key) => Err(std::io::Error::other(format!(
            "ADR 0109 S3: the failed re-seat swap of {} is not resolved yet; the roster write waits for it",
            LogHexId::group(key)
        ))),
        None => Ok(()),
    }
}

/// Record the failed swap of `key`, or (`None`) end its refusal.
async fn set_failed_swap(state: &AppState, key: &str, failed: Option<FailedSwap>) {
    let mut inner = state.group_recovery.inner.lock().await;
    match failed {
        Some(failed) => {
            inner.failed_swaps.insert(key.to_string(), failed);
        }
        None => {
            inner.failed_swaps.remove(key);
        }
    }
}

/// #1645: put back the files of a rolled-back swap of `stable` that a
/// tick before could not put back, before anything else of the re-seat
/// runs. Returns whether the re-seat may go on: no failed swap of
/// `stable` is left, or it is [`FailedSwap::Forward`] (the swap's own
/// tree write retries it). Caller holds the group membership lock.
async fn resolve_failed_swap(state: &AppState, stable: &str) -> bool {
    let _persistence_guard = state.named_groups_persistence_lock.lock().await;
    let failed = {
        let mut inner = state.group_recovery.inner.lock().await;
        let key = inner
            .failed_swaps
            .iter()
            .find(|(_, failed)| matches!(failed, FailedSwap::Rollback { stable: s, .. } if s == stable))
            .map(|(key, _)| key.clone());
        key.and_then(|key| inner.failed_swaps.remove(&key).map(|failed| (key, failed)))
    };
    let Some((key, failed)) = failed else {
        return true;
    };
    if let FailedSwap::Rollback {
        expected, before, ..
    } = &failed
    {
        if finish_failed_swap(state, stable, &key, *expected, before).await {
            tracing::info!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the failed swap's files are back; roster writes resume");
            return true;
        }
    }
    set_failed_swap(state, &key, Some(failed)).await;
    false
}

/// #1645: put `before` (the original pair) back after a failed swap that
/// made the `Swapping` mark and, when all of it is durable, end the swap
/// ([`end_swap_after_rollback`]). Returns whether that is all durable.
/// A group that memory holds as withdrawn gets the withdrawn repair
/// instead: it removes the tree and the journals, so no pair is left to
/// mix, and a restore would undo the withdrawal on disk. Caller holds
/// `named_groups_persistence_lock`.
async fn finish_failed_swap(
    state: &AppState,
    stable: &str,
    key: &str,
    expected: [u8; 32],
    before: &SwapBefore,
) -> bool {
    match super::repair_withdrawn_named_groups_json_and_wipe_key_material_locked(
        state,
        key,
        Some(stable),
        "reseat_failed_swap",
    )
    .await
    {
        Ok(true) => return end_swap_after_rollback(state, stable, key, expected).await,
        Ok(false) => {}
        Err(error) => {
            tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the withdrawn repair after a failed swap did not complete; the swap stays recoverable and is retried: {error}");
            return false;
        }
    }
    rollback_swap_files(state, stable, key, before).await
        && end_swap_after_rollback(state, stable, key, expected).await
}

/// #1645: the swap that made the mark changed no file (or the files are
/// already the original pair): end it, or, when that fails, refuse other
/// roster writes until a tick ends it.
async fn end_or_pin_rollback(
    state: &AppState,
    stable: &str,
    key: &str,
    expected: [u8; 32],
    before: SwapBefore,
) {
    if !end_swap_after_rollback(state, stable, key, expected).await {
        pin_rollback(state, stable, key, expected, before).await;
    }
}

async fn pin_rollback(
    state: &AppState,
    stable: &str,
    key: &str,
    expected: [u8; 32],
    before: SwapBefore,
) {
    let failed = FailedSwap::Rollback {
        stable: stable.to_string(),
        expected,
        before,
    };
    set_failed_swap(state, key, Some(failed)).await;
}

/// §3 step 3 (#1567): mark the journal `Swapping` and, in the same hold of
/// `named_groups_persistence_lock`, put the staged record and its tree on
/// disk in one TreeKEM persist transaction. Until then the snapshot file
/// keeps the original's tree (`reseat_snapshot_cover`), as the roster
/// files keep the original record. `Swapping` ends both covers, so no
/// other roster write may come between it and the tree write: the lock
/// keeps the original record and tree, or the staged record and tree,
/// paired on disk at every point. A crash before the transaction's
/// journal loads the original pair, which rolls back.
///
/// A failed tree write keeps its transaction journals, so until the
/// rollback is durable a restart replays the staged record and its tree
/// together, and the `Swapping` journal swaps them in (#1645, Codex P1 on
/// #1683). The rollback puts the original's snapshot back, then the
/// Home-Suite sidecar, then `named_groups.json`. Only when all three are
/// durable does [`end_swap_after_rollback`] put the journal back to
/// `Staging` (in memory first, so the covers apply again), discard the
/// transaction journals and make the phase durable: a restart then loads
/// the original pair, which rolls back. A restore that fails keeps the
/// journals and `Swapping`. Either way the next tick retries. A group with
/// no tree (GSS) needs only the mark. Returns whether the swap may go on
/// to [`lift_staging_marker`].
///
/// A write that stops before its commit point (#1645, Codex P1 round 4),
/// or that does not run, changed no file: the original pair is still on
/// disk and no journal replays the staged pair. When this call made the
/// mark, the swap ends at once ([`end_swap_after_rollback`]), with no
/// file restore that can fail. Before the fix the restore ran, and when
/// it failed (an unwritable `treekem/`) memory kept `Swapping` with the
/// covers off and no journal: a later whole-roster save wrote the staged
/// record beside the original's tree, and a restart paired them.
///
/// A write that fails after its commit point can leave mixed files, which
/// only its journals repair. From that failure until the staged pair is
/// durable or the original files are all back, every other whole-roster
/// write is refused ([`refuse_roster_write_during_failed_swap`]), so no
/// write can make the journals stale. The swap that made the mark puts
/// the original pair back ([`FailedSwap::Rollback`]). A retry of a
/// `Swapping` journal puts nothing back and retries forward
/// ([`FailedSwap::Forward`]): the files it could read are not known to be
/// a matching pair, and its tree can be older than the tree in memory.
/// A withdrawn group's repair leaves no pair to mix; the swap ends.
async fn swap_staged_tree(
    state: &AppState,
    stable: &str,
    journal: &ReseatJournalV1,
    key: &str,
    source: StagedSource,
) -> bool {
    let expected = journal.record_digest;
    let tree = source.of(&state.treekem_groups).await.get(key).cloned();
    // Lock order as every TreeKEM persist: the group, then the store.
    let guard = match tree.as_ref() {
        Some(tree) => Some(tree.lock().await),
        None => None,
    };
    let _persistence_guard = state.named_groups_persistence_lock.lock().await;
    // F5: another group's failed swap refuses every roster write, so this
    // one would only mark `Swapping` and end it again. Wait for it.
    if refuse_roster_write_during_failed_swap(state, Some(key))
        .await
        .is_err()
    {
        return false;
    }
    let marked_here = journal.phase != ReseatPhase::Swapping;
    // The original pair's snapshot state and both roster stores, which a
    // failed tree write puts back. Read them before the `Swapping` mark
    // below: that mark ends the covers. A retry of a `Swapping` journal
    // reads nothing: it never puts files back ([`FailedSwap::Forward`]).
    let before = if guard.is_some() && marked_here {
        let read = async {
            let cover = match super::reseat_snapshot_cover(state, key).await? {
                Some(cover) => cover,
                None => super::snapshot_file_cover(state, key).await?,
            };
            anyhow::Ok(SwapBefore {
                cover,
                rosters: super::read_roster_stores(state).await?,
            })
        };
        match read.await {
            Ok(before) => Some(before),
            Err(error) => {
                tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the swap is retried: {error}");
                return false;
            }
        }
    } else {
        None
    };
    if marked_here {
        let mut marked = false;
        let marked_ref = &mut marked;
        let durable = update_sidecar(state, stable, move |body| {
            if let Some(open) = body.reseat_journal.as_mut() {
                if open.record_digest == expected {
                    open.phase = ReseatPhase::Swapping;
                    *marked_ref = true;
                }
            }
        })
        .await;
        if !(durable && marked) {
            return false;
        }
    }
    let Some(guard) = guard else {
        // No tree: the roster write of [`lift_staging_marker`] makes the
        // swapped-in record durable.
        promote_staging(state, key, true).await;
        return true;
    };
    let Some(info) = source.of(&state.named_groups).await.get(key).cloned() else {
        // No write ran: the files are as they were.
        if let Some(before) = before {
            end_or_pin_rollback(state, stable, key, expected, before).await;
        }
        return false;
    };
    let result =
        super::persist_treekem_and_named_groups_atomic_locked(state, key, info, &guard, true).await;
    let error = match result {
        // Past the commit point; the staged pair is durable, or the
        // journals replay it.
        Err(error) if !super::self_leave_persist_left_epoch_installed(&error) => error,
        _ => {
            set_failed_swap(state, key, None).await;
            // The tree write put the staged record in the live map; its
            // tree follows under the same locks.
            promote_staging(state, key, false).await;
            return true;
        }
    };
    if super::persist_withdrew_group(&error) {
        // The withdrawn repair wrote the rosters and removed the tree and
        // the journals: no pair is left to mix, and putting `before` back
        // would undo the withdrawal on disk.
        tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the group is withdrawn; the swap ends: {error}");
        set_failed_swap(state, key, None).await;
        if marked_here {
            // A failure is logged; the journal stays `Swapping` and a restart
            // loads the withdrawn record.
            let _ = end_swap_after_rollback(state, stable, key, expected).await;
        }
        return false;
    }
    if super::persist_stopped_before_commit(&error) {
        // No live file changed. The swap that made the mark ends at once,
        // with no file restore that can fail. A retry of a `Swapping`
        // journal stays as it is: a pin from an earlier attempt stays, and
        // its journals still replay the staged pair.
        tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the staged tree write stopped before its commit point; the files are unchanged and the swap is retried: {error}");
        if let Some(before) = before {
            end_or_pin_rollback(state, stable, key, expected, before).await;
        }
        return false;
    }
    // Past the commit point: the files can be mixed, and the journals
    // replay the staged pair. Until the files are a matching pair again no
    // other roster write runs.
    match before {
        Some(before) => {
            tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the staged tree is not durable yet; the original pair is put back and the swap is retried: {error}");
            if !finish_failed_swap(state, stable, key, expected, &before).await {
                pin_rollback(state, stable, key, expected, before).await;
            }
        }
        None => {
            tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the staged tree is not durable yet; its journals replay the staged pair and the write is retried: {error}");
            set_failed_swap(state, key, Some(FailedSwap::Forward)).await;
        }
    }
    false
}

/// #1645 (Codex P1 on #1645 and #1683): the original's files are all back
/// after a failed swap (restored, or never changed); end the swap. The
/// caller holds `named_groups_persistence_lock` throughout, so no other
/// roster or tree write runs between the steps. The order makes every
/// point recover to the original pair, whichever write fails:
///
/// 1. The swap's transaction journals are discarded, durably (the
///    removal and its directory sync are checked). They hold the staged
///    pair, and the files no longer need them: a restart replays nothing
///    and loads the original pair. When the discard fails, the swap stays
///    `Swapping`, the journals can still replay the staged pair, and every
///    other roster write is refused until the next tick retries.
/// 2. The journal goes back to `Staging` in memory and the refusal ends.
///    The covers apply again before the lock is released, so every later
///    write (of any group) keeps the original record and the original's
///    tree on disk. With `Swapping` left in memory, a later whole-roster
///    save wrote the staged record beside the restored original tree.
/// 3. The durable `Staging` write, checked. When it fails, the sidecar on
///    disk still says `Swapping`; a restart loads the original record
///    under it, and `staged_join_lost` rolls back to the original pair.
///    The next sidecar write of the group, or the next swap attempt,
///    makes the memory phase durable.
async fn end_swap_after_rollback(
    state: &AppState,
    stable: &str,
    key: &str,
    expected: [u8; 32],
) -> bool {
    if let Err(error) = super::discard_seal_journal_pair_durable(state, key).await {
        tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: cannot discard the failed swap's journals; the swap stays recoverable and is retried: {error}");
        return false;
    }
    state
        .group_recovery
        .reset_phase_in_memory(stable, expected)
        .await;
    #[cfg(test)]
    let fault = state.group_recovery.inner.lock().await.swap_rollback_stop
        == Some(SwapRollbackStop::PhaseWriteFails);
    #[cfg(not(test))]
    let fault = false;
    let durable = !fault
        && update_sidecar_if(state, stable, |body| {
            reset_journal_to_staging(body, expected)
        })
        .await
            == SidecarWrite::Written;
    if !durable {
        tracing::warn!(group_id = %LogHexId::group(stable), "ADR 0109 S3: the rolled-back swap's `Staging` phase is not durable yet; the original pair is on disk and a restart rolls back to it");
    }
    true
}

/// Put `body`'s re-seat journal `expected` back to `Staging`. Returns
/// whether that journal is open.
fn reset_journal_to_staging(body: &mut GroupRecoveryV1, expected: [u8; 32]) -> bool {
    match body.reseat_journal.as_mut() {
        Some(open) if open.record_digest == expected => {
            open.phase = ReseatPhase::Staging;
            true
        }
        _ => false,
    }
}

/// #1645: put the original's snapshot state and both roster stores back
/// after a failed swap, in the order the swap's transaction wrote them.
/// Returns whether all three are durable.
async fn rollback_swap_files(
    state: &AppState,
    stable: &str,
    key: &str,
    before: &SwapBefore,
) -> bool {
    let rosters = &before.rosters;
    #[cfg(test)]
    let stop = state.group_recovery.inner.lock().await.swap_rollback_stop;
    let snapshot = match () {
        #[cfg(test)]
        () if stop == Some(SwapRollbackStop::SnapshotRestoreFails) => {
            Err(anyhow::anyhow!("test fault"))
        }
        () => super::restore_reseat_snapshot_cover(state, key, before.cover.clone()).await,
    };
    if let Err(error) = snapshot {
        tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: cannot put the original's TreeKEM snapshot back after a failed swap; the staged pair stays recoverable: {error}");
        return false;
    }
    #[cfg(test)]
    if stop == Some(SwapRollbackStop::AfterSnapshot) {
        return false;
    }
    let sidecar = match () {
        #[cfg(test)]
        () if stop == Some(SwapRollbackStop::SidecarRestoreFails) => {
            Err(anyhow::anyhow!("test fault"))
        }
        () => super::restore_home_suite_store(state, rosters).await,
    };
    if let Err(error) = sidecar {
        tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: cannot put the Home-Suite sidecar back after a failed swap; the staged pair stays recoverable: {error}");
        return false;
    }
    #[cfg(test)]
    if stop == Some(SwapRollbackStop::AfterSidecar) {
        return false;
    }
    if let Err(error) = super::restore_named_store(state, rosters).await {
        tracing::error!(group_id = %LogHexId::group(stable), "ADR 0109 S3: cannot put named_groups.json back after a failed swap; the staged pair stays recoverable: {error}");
        return false;
    }
    true
}

/// §3 step 3: the swap's roster write. The staged record (every record of
/// `stable`) drops the journalled original's marker, which it held since
/// its first write, and the legacy files get it. The live map changes only
/// when that write is Durable: a failed or `ReplacedNotDurable` write, or a
/// crash, keeps the marker. Returns whether the write is Durable.
async fn lift_staging_marker(state: &AppState, stable: &str, journal: &ReseatJournalV1) -> bool {
    let held = journal.original_marker();
    let stable = stable.to_string();
    let journal = journal.clone();
    // The write runs also when no record holds a marker: it is the swap's
    // durable legacy write of the staged record. The journalled original
    // keeps its marker: only a staged record drops it.
    let outcome = super::persist_named_groups_quarantine_clear_durable_only(state, move |groups| {
        for info in groups.values_mut().filter(|info| {
            info.stable_group_id() == stable && !is_journalled_original(info, &journal)
        }) {
            if held.is_some() && info.fork_quarantine == held {
                info.fork_quarantine = None;
                info.reset_fork_evidence_after_quarantine_clear();
            }
        }
        true
    })
    .await;
    matches!(outcome, Ok(super::AtomicWriteOutcome::Durable))
}

/// Swap in the staged record of `stable` now if it is seated. A no-op when
/// no re-seat journal is open.
async fn swap_now_if_seated(state: &AppState, stable: &str) {
    let _ = swap_if_seated(state, stable).await;
}

/// Swap, fail or roll back each open journal (§3 steps 3 and 4, and the
/// crash resume "from the journal's phase").
///
/// - `Prepared`: unless this process is preparing it right now, the
///   preparation was interrupted (a crash, or a failed step whose rollback
///   was not yet durable). Roll it back; it never swaps.
/// - `Staging`/`Swapping`: swap a bound result; roll back when the staged
///   join ended, its deadline passed, or its in-memory stub was lost.
async fn reseat_progress(state: &Arc<AppState>) {
    let (journals, preparing): (Vec<(String, ReseatJournalV1)>, HashSet<String>) = {
        let inner = state.group_recovery.inner.lock().await;
        (
            inner
                .sidecars
                .iter()
                .filter_map(|(group, body)| body.reseat_journal.clone().map(|j| (group.clone(), j)))
                .collect(),
            inner.staging_live.clone(),
        )
    };
    for (stable, journal) in journals {
        if journal.phase == ReseatPhase::Prepared {
            if !preparing.contains(&stable) {
                rollback_reseat(
                    state,
                    &stable,
                    journal.record_digest,
                    "reseat_preparation_interrupted",
                )
                .await;
            }
            continue;
        }
        if swap_if_seated(state, &stable).await {
            continue;
        }
        let live = live_record_for(state, &stable).await;
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
            rollback_reseat(state, &stable, journal.record_digest, "staged_join_ended").await;
        } else if staged_join_lost(
            &journal,
            live.as_ref().map(|(_, info)| info),
            preparing.contains(&stable),
        ) {
            // No staged join runs in this process (a restart lost it) and
            // no staged record is durable: roll back.
            rollback_reseat(state, &stable, journal.record_digest, "staged_join_lost").await;
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
            SidecarFault::QuarantineDeferred { file } => serde_json::json!({
                "state": "recovery_deferred", "cause": HOST_COMMIT_PENDING, "file": file,
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
    let armed = armed_admin_ata(state, info).await.is_some()
        || exhausted_segment(state, info).await.is_some();
    let inner = state.group_recovery.inner.lock().await;
    let kept_chain = inner
        .sidecars
        .get(info.stable_group_id())
        .is_some_and(|body| !body.served_chain.is_empty());
    // A staged re-seat record's marker is the original's (§3 step 2); its
    // join is not held, so its poll ends as an ordinary join.
    let own_marker =
        info.fork_quarantine.is_some() && state.group_recovery.held_reseat_marker(info).is_none();
    // H-S3-t (4), §8: inside an uncommitted ADR 0094 trial S3 cannot keep
    // the served chain (no new sidecar before host commit), but the wait
    // is typed: the attempt holds as `recovery_deferred`, not a bare
    // `timed_out` that drops the contained stub.
    let view = inner.subjects.get(info.stable_group_id()).map(|s| &s.view);
    let deferred = matches!(
        view,
        Some(SubjectView::Deferred { cause }) if *cause == HOST_COMMIT_PENDING
    );
    if !(armed || (own_marker && (kept_chain || deferred))) {
        return None;
    }
    Some(match view {
        Some(SubjectView::CatchingUp { .. }) => "catching_up",
        Some(SubjectView::Readmission { .. }) => "readmission_required",
        Some(SubjectView::Reseat { .. } | SubjectView::ReseatInProgress { .. }) => {
            "reseat_required"
        }
        Some(SubjectView::Deferred { .. }) => "recovery_deferred",
        _ => "awaiting_attestation",
    })
}

/// Test only: open a `Staging` re-seat journal for `original` (live key
/// `key`), signed by this node, as [`prepare_reseat`] leaves it after it
/// opens the staging slot. Returns whether the sidecar write is durable.
#[cfg(test)]
pub(in crate::server) async fn open_staging_journal_for_test(
    state: &AppState,
    key: &str,
    original: &GroupInfo,
) -> anyhow::Result<bool> {
    let keypair = state.agent.identity().agent_keypair();
    let local = local_hex(state);
    let authorisation = ReseatAuthorisation::sign(
        ReseatAuthorisationFields {
            group: original.stable_group_id().to_string(),
            subject: local.clone(),
            basis: ReseatBasis::Removal {
                revision: original.state_revision,
                state_hash: original.state_hash.clone(),
            },
            invite_secret_hash: s3::invite_secret_hash("secret"),
            invite_base_revision: original.state_revision,
            invite_base_state_hash: original.state_hash.clone(),
            signer: local,
            reason_hash: s3::reason_hash("r"),
            expires_at_ms: u64::MAX / 2,
        },
        keypair,
    )?;
    let live_record = serde_json::to_vec(original)?;
    let journal = ReseatJournalV1 {
        authorisation,
        invite: String::new(),
        record_digest: *blake3::hash(&live_record).as_bytes(),
        phase: ReseatPhase::Staging,
        live_key: key.to_string(),
        live_record,
        live_tree: None,
        started_at_ms: now_ms(),
    };
    Ok(
        update_sidecar(state, original.stable_group_id(), move |body| {
            body.reseat_journal = Some(journal);
        })
        .await,
    )
}

/// Test only: record a §2 attestation conflict on `current`'s head, as
/// [`arm_from_response`] leaves it: an active ATA and a conflicting ATA,
/// both from the head, that diverge at the first link. The common prefix
/// is empty, so [`conflict_admits_commit`] admits no commit past the head.
/// Returns whether the sidecar write is durable.
#[cfg(test)]
pub(in crate::server) async fn record_conflict_at_head_for_test(
    state: &AppState,
    current: &GroupInfo,
) -> anyhow::Result<bool> {
    let signer = x0x::identity::AgentKeypair::generate()?;
    let ata = |next: &str| {
        AdminTerminalAttestation::sign(
            AtaFields {
                group: current.stable_group_id().to_string(),
                subject: local_hex(state),
                attested_by: hex::encode(signer.agent_id().as_bytes()),
                signer_public_key: hex::encode(signer.public_key().as_bytes()),
                from_revision: current.state_revision,
                from_state_hash: current.state_hash.clone(),
                sequence: vec![next.to_string()],
                segment_terminal_revision: current.state_revision + 1,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &signer,
        )
    };
    let active = ata("a1")?;
    let conflict = ata("b1")?;
    Ok(
        update_sidecar(state, current.stable_group_id(), move |body| {
            body.active_ata = Some(active);
            body.attestation_conflict = Some(conflict);
        })
        .await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A contained original record (marker set) and its re-seat journal
    /// in `phase`, built without a daemon. The subject is a second agent.
    fn pure_reseat(
        phase: ReseatPhase,
    ) -> anyhow::Result<(GroupInfo, ReseatJournalV1, x0x::identity::AgentKeypair)> {
        let keypair = x0x::identity::AgentKeypair::generate()?;
        let signer = hex::encode(keypair.agent_id().as_bytes());
        let subject = hex::encode(
            x0x::identity::AgentKeypair::generate()?
                .agent_id()
                .as_bytes(),
        );
        let mut info = GroupInfo::new(
            "adr0109-pure".to_string(),
            String::new(),
            keypair.agent_id(),
            "2109".repeat(16),
        );
        info.seal_commit(&keypair, 1_000)?;
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: info.state_revision,
            state_hash: "sibling".to_string(),
            committed_by: signer.clone(),
            observed_at_ms: 1,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        });
        let authorisation = ReseatAuthorisation::sign(
            ReseatAuthorisationFields {
                group: info.stable_group_id().to_string(),
                subject,
                basis: ReseatBasis::Removal {
                    revision: info.state_revision,
                    state_hash: info.state_hash.clone(),
                },
                invite_secret_hash: s3::invite_secret_hash("secret"),
                invite_base_revision: info.state_revision,
                invite_base_state_hash: info.state_hash.clone(),
                signer,
                reason_hash: s3::reason_hash("r"),
                expires_at_ms: 10_000,
            },
            &keypair,
        )?;
        let live_record = serde_json::to_vec(&info)?;
        let journal = ReseatJournalV1 {
            authorisation,
            invite: String::new(),
            record_digest: *blake3::hash(&live_record).as_bytes(),
            phase,
            live_key: info.mls_group_id.clone(),
            live_record,
            live_tree: None,
            started_at_ms: 0,
        };
        Ok((info, journal, keypair))
    }

    /// #1533 review (Codex P1, re-seat containment): at every crash point
    /// before the swap, the legacy files hold the original record with its
    /// marker, whatever the live map holds. Before the fix the move aside
    /// removed it from disk, so a crash or a downgrade loaded no
    /// containment (or the staged record).
    #[test]
    fn the_legacy_view_keeps_the_original_containment_until_the_swap() -> anyhow::Result<()> {
        let (original, journal, keypair) = pure_reseat(ReseatPhase::Staging)?;
        let key = journal.live_key.clone();
        let mut staged = original.clone();
        staged.fork_quarantine = None;
        staged.name = "staged".to_string();
        staged.seal_commit(&keypair, 2_000)?;
        let none = HashSet::new();
        for (phase, live) in [
            (ReseatPhase::Prepared, Some(original.clone())),
            (ReseatPhase::Staging, None),
            (ReseatPhase::Staging, Some(staged.clone())),
        ] {
            let mut open = journal.clone();
            open.phase = phase;
            let groups: HashMap<String, GroupInfo> =
                live.into_iter().map(|info| (key.clone(), info)).collect();
            let view = reseat_overlay(&groups, std::slice::from_ref(&open), &none)
                .expect("an open journal overlays the legacy view");
            let on_disk = view.get(&key).expect("the group stays on disk");
            assert!(on_disk.fork_quarantine.is_some(), "{phase:?}: the marker");
            assert_eq!(on_disk.state_hash, original.state_hash, "{phase:?}");
            assert_eq!(view.len(), 1, "{phase:?}");
        }
        // Placeheld: the original's S3 placeholder, with no Active seat.
        let placeheld = HashSet::from([original.stable_group_id().to_string()]);
        let view = reseat_overlay(&HashMap::new(), std::slice::from_ref(&journal), &placeheld)
            .expect("overlay");
        assert!(view[&key].fork_quarantine.is_some());
        assert_eq!(view[&key].active_members().count(), 0);
        // `Swapping` lifts the overlay: the staged record is written.
        let mut swapping = journal;
        swapping.phase = ReseatPhase::Swapping;
        let groups = HashMap::from([(key, staged)]);
        assert!(reseat_overlay(&groups, &[swapping], &none).is_none());
        Ok(())
    }

    /// #1533 review (Codex P1, re-seat containment): while the re-seat join
    /// is staged (`Prepared` or `Staging`), the one hold gives the staged
    /// record (here Active and with no marker of its own) the original's
    /// marker, in a single record or a roster. The hold ends at `Swapping`
    /// (the swap's own write lifts it) and when the journal closes.
    #[test]
    fn a_staged_reseat_record_holds_the_original_marker_until_swapping() -> anyhow::Result<()> {
        let (original, journal, keypair) = pure_reseat(ReseatPhase::Staging)?;
        let key = journal.live_key.clone();
        let stable = original.stable_group_id().to_string();
        let original_marker = original.fork_quarantine.clone();
        let mut staged = original.clone();
        staged.fork_quarantine = None;
        staged.seal_commit(&keypair, 2_000)?;
        let runtime = S3Runtime::default();
        let body_in = |phase| {
            let mut journal = journal.clone();
            journal.phase = phase;
            GroupRecoveryV1 {
                reseat_journal: Some(journal),
                ..GroupRecoveryV1::default()
            }
        };
        for phase in [ReseatPhase::Prepared, ReseatPhase::Staging] {
            runtime.refresh_staging(&stable, Some(&body_in(phase)));
            let mut record = staged.clone();
            assert!(runtime.hold_reseat_marker(&mut record));
            assert_eq!(record.fork_quarantine, original_marker);
            let mut roster = HashMap::from([(key.clone(), staged.clone())]);
            assert!(runtime.hold_reseat_markers(&mut roster));
            assert_eq!(roster[&key].fork_quarantine, original_marker);
            // A record that already has a marker keeps its own.
            assert!(!runtime.hold_reseat_marker(&mut record));
        }
        for body in [body_in(ReseatPhase::Swapping), GroupRecoveryV1::default()] {
            runtime.refresh_staging(&stable, Some(&body));
            let mut record = staged.clone();
            assert!(!runtime.hold_reseat_marker(&mut record));
            assert!(record.fork_quarantine.is_none());
        }
        Ok(())
    }

    /// #1533 review: after a restart the original is live again (from the
    /// legacy files). A `Staging` journal, or a `Swapping` one whose staged
    /// record never became durable, is lost and rolls back; it never waits
    /// for the authorisation deadline with the staged state gone.
    #[test]
    fn a_reseat_cut_before_the_durable_swap_rolls_back_after_restart() -> anyhow::Result<()> {
        let (original, staging, keypair) = pure_reseat(ReseatPhase::Staging)?;
        let mut reloaded = original.clone();
        reloaded.name = "re-encoded on load".to_string();
        let mut staged = original.clone();
        staged.fork_quarantine = None;
        staged.seal_commit(&keypair, 2_000)?;
        assert!(is_journalled_original(&reloaded, &staging));
        assert!(!is_journalled_original(&staged, &staging));
        assert!(staged_join_lost(&staging, Some(&reloaded), false));
        assert!(staged_join_lost(&staging, None, false));
        assert!(
            !staged_join_lost(&staging, Some(&reloaded), true),
            "in-process join"
        );
        let mut swapping = staging;
        swapping.phase = ReseatPhase::Swapping;
        assert!(staged_join_lost(&swapping, Some(&reloaded), false));
        assert!(
            !staged_join_lost(&swapping, Some(&staged), false),
            "swap resumes"
        );
        Ok(())
    }

    /// #1533 review (Codex P1, re-seat delivery): the write of a re-seat
    /// exchange is refused once the issuer's own record is contained, the
    /// authorisation expired, or it is no longer the issued one.
    #[test]
    fn a_reseat_write_needs_an_uncontained_issuer_and_the_current_authorisation(
    ) -> anyhow::Result<()> {
        let (mut info, journal, _) = pure_reseat(ReseatPhase::Staging)?;
        info.fork_quarantine = None;
        let authorisation = journal.authorisation;
        let subject = authorisation.fields.subject.clone();
        let digest = authorisation.digest();
        let issued = vec![IssuedReseatV1 {
            authorisation,
            invite: String::new(),
            issued_at_ms: 0,
        }];
        assert!(reseat_write_admits(
            &info, false, &issued, &subject, &digest, 5_000
        ));
        assert!(
            !reseat_write_admits(&info, true, &issued, &subject, &digest, 5_000),
            "issuer contained"
        );
        assert!(
            !reseat_write_admits(&info, false, &issued, &subject, &digest, 10_000),
            "expired"
        );
        assert!(
            !reseat_write_admits(&info, false, &issued, &subject, &[0; 32], 5_000),
            "replaced"
        );
        assert!(
            !reseat_write_admits(&info, false, &[], &subject, &digest, 5_000),
            "consumed"
        );
        Ok(())
    }

    /// #1533 review (Codex P2): only a current verified positive advert
    /// admits an S3 write; unknown (legacy) or expired support sends
    /// nothing.
    #[test]
    fn s3_writes_need_current_verified_support() {
        assert!(capability_admits(Some(true)));
        assert!(!capability_admits(Some(false)));
        assert!(!capability_admits(None));
    }

    #[test]
    fn responder_budget_limits_each_requester_and_builds() {
        let now = Instant::now();
        let mut budget = ResponderBudget::default();
        assert_eq!(budget.admit([1; 32], now), Admission::Build);
        for id in 2..=4u8 {
            assert_eq!(budget.admit([id; 32], now), Admission::Build);
        }
        assert_eq!(
            budget.admit([9; 32], now),
            Admission::Drop,
            "four concurrent builds"
        );
        budget.finish(10);
        assert_eq!(budget.admit([9; 32], now), Admission::Build);
        for _ in 0..s3::RESPONDER_SIGNATURES_PER_MINUTE {
            assert!(budget.may_sign());
        }
        assert!(!budget.may_sign());
        let later = now + Duration::from_secs(61);
        budget.roll(later);
        assert!(budget.may_sign());
        assert!(budget.per_requester.is_empty());
    }

    /// Codex P2 (#1533 r10), ADR 0109 §11: a `rate_limited` refusal takes
    /// a build slot and counts against the byte budget, so a request flood
    /// from one capable peer stops at the concurrent-build and byte limits.
    /// Before the fix every refused request started a response exchange
    /// outside both.
    #[test]
    fn rate_limited_refusals_are_bounded_and_accounted() {
        let now = Instant::now();
        let mut budget = ResponderBudget::default();
        assert_eq!(budget.admit([1; 32], now), Admission::Build);
        budget.finish(10);
        // H-S3-d7: every later request in the interval gets the refusal...
        assert_eq!(budget.admit([1; 32], now), Admission::Refuse);
        assert_eq!(budget.building, 1, "the refusal holds a build slot");
        budget.finish(20);
        assert_eq!(budget.bytes, 30, "the refusal's bytes count");
        // ...while it fits the concurrent builds: a flood in flight stops.
        for _ in 0..s3::RESPONDER_CONCURRENT_BUILDS {
            assert_eq!(budget.admit([1; 32], now), Admission::Refuse);
        }
        for _ in 0..100 {
            assert_eq!(budget.admit([1; 32], now), Admission::Drop);
        }
        assert_eq!(budget.admit([6; 32], now), Admission::Drop);
        // And at the byte budget.
        let mut spent = ResponderBudget::default();
        assert_eq!(spent.admit([1; 32], now), Admission::Build);
        spent.finish(s3::RESPONDER_BYTES_PER_MINUTE);
        assert_eq!(spent.admit([1; 32], now), Admission::Drop);
        // The next interval starts again.
        let later = now + Duration::from_secs(61);
        assert_eq!(
            budget.admit([1; 32], later),
            Admission::Drop,
            "builds still held"
        );
        for _ in 0..s3::RESPONDER_CONCURRENT_BUILDS {
            budget.finish(0);
        }
        assert_eq!(budget.admit([1; 32], later), Admission::Build);
    }

    /// Codex P1 (#1533 r10), ADR 0109 §3 step 2: while a re-seat join is
    /// staged, the live map holds the staged record, but the placeholder,
    /// the authoritative record behind it and the S3 state in the sidecar
    /// stay the journalled original's until the swap. Before the fix the
    /// placeholder maintenance read the staged record (off the ATA's
    /// chain, so on its own it needs no placeholder), dropped the
    /// placeholder and the authoritative record, and the legacy views got
    /// the original's real record: no downgrade protection before the
    /// durable swap. Any S3 path could also clear the original's ATA.
    #[tokio::test]
    async fn a_staged_reseat_keeps_the_originals_placeholder_and_s3_state() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);
        let original = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("armed record"))?;
        assert!(open_staging_journal_for_test(&state, &key, &original).await?);
        // The staged join under the key, at a head off the ATA's chain.
        let mut staged = original.clone();
        staged.seal_commit(&admin, 2_000)?;
        assert!(armed_admin_ata(&state, &staged).await.is_none());
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), staged.clone());

        ensure_placeholders(&state).await;
        assert!(is_placeheld(&state, &stable), "the placeholder stays");
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        ensure_placeholders(&state).await;
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(s3::is_s3_placeholder(&legacy), "downgrade protection kept");
        assert_eq!(legacy.state_hash, original.state_hash);
        let body = sidecar_on_disk(&state, &stable).await?;
        let authoritative: GroupInfo = serde_json::from_slice(
            body.authoritative_record
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("authoritative record"))?,
        )?;
        assert_eq!(authoritative.state_hash, original.state_hash);
        assert!(body.active_ata.is_some());

        // No S3 path that reads the staged record changes the original's
        // S3 state: a retirement, a reply's conflict or a new ATA.
        assert!(!update_sidecar(&state, &stable, |body| body.active_ata = None).await);
        assert!(!update_sidecar(&state, &stable, |body| body.served_chain.push(Vec::new())).await);
        let kept = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(kept.active_ata.is_some() && kept.served_chain.is_empty());
        // Other fields still move (the journal's own phase, issued
        // re-seats), and the swap may change the state once `Swapping`.
        assert!(
            update_sidecar(&state, &stable, |body| {
                if let Some(journal) = body.reseat_journal.as_mut() {
                    journal.phase = ReseatPhase::Swapping;
                }
            })
            .await
        );
        assert!(update_sidecar(&state, &stable, |body| body.active_ata = None).await);
        Ok(())
    }

    /// Codex P1 (#1533 r10), ADR 0109 §2/§3: a reply that is only the
    /// sender's word (`not_on_chain`, `on_chain`, a refusal) moves the
    /// recovery state only when it comes from the target this node asked,
    /// for the head it asked about. Before the fix any verified peer that
    /// knew the group and the head could send `not_on_chain` or
    /// `banned_or_revoked` and change the view and the round.
    #[tokio::test]
    async fn only_the_asked_target_moves_the_recovery_state() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (_key, info, _ata, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        let stranger = x0x::identity::AgentKeypair::generate()?;
        let response = |answer| GroupAttestResponseV1 {
            group: stable.clone(),
            subject: *state.agent.agent_id().as_bytes(),
            for_head_state_hash: info.state_hash.clone(),
            answer,
        };
        let not_on_chain = || {
            AttestAnswer::NotOnChain(s3::AdminHead {
                revision: 9,
                state_hash: "f".repeat(64),
            })
        };
        let banned = || AttestAnswer::Refused(AttestRefusalReason::BannedOrRevoked);
        // Nobody was asked: nothing moves, from anyone.
        for sender in [stranger.agent_id(), admin.agent_id()] {
            handle_response(&state, sender, response(not_on_chain())).await;
            handle_response(&state, sender, response(banned())).await;
        }
        assert!(!state
            .group_recovery
            .inner
            .lock()
            .await
            .subjects
            .contains_key(&stable));

        // The admin is asked about this head; a stranger's reply still
        // changes nothing.
        let asked_at = Instant::now();
        state
            .group_recovery
            .inner
            .lock()
            .await
            .subjects
            .entry(stable.clone())
            .or_insert_with(|| SubjectState::new(asked_at, info.state_revision))
            .pending = Some((
            *admin.agent_id().as_bytes(),
            asked_at,
            info.state_hash.clone(),
        ));
        handle_response(&state, stranger.agent_id(), response(banned())).await;
        handle_response(&state, stranger.agent_id(), response(not_on_chain())).await;
        {
            let inner = state.group_recovery.inner.lock().await;
            let subject = inner
                .subjects
                .get(&stable)
                .ok_or_else(|| anyhow::anyhow!("subject"))?;
            assert!(subject.pending.is_some(), "the round still waits");
            assert!(subject.asked.is_empty());
            assert!(!matches!(
                subject.view,
                SubjectView::Reseat { .. } | SubjectView::Refused { .. }
            ));
        }
        // The asked target's reply counts.
        handle_response(&state, admin.agent_id(), response(not_on_chain())).await;
        let inner = state.group_recovery.inner.lock().await;
        let subject = inner
            .subjects
            .get(&stable)
            .ok_or_else(|| anyhow::anyhow!("subject"))?;
        assert!(subject.pending.is_none());
        assert!(matches!(
            subject.view,
            SubjectView::Reseat {
                cause: "not_on_chain",
                ..
            }
        ));
        Ok(())
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
            Err("reseat_invite_unpaired")
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

    /// #1533 review (Codex P1): a re-seat credential of an owner-axis group
    /// is a device-admission credential, so a session bearer never mints
    /// one. This node holds no owner key, so the route takes the
    /// promoted-admin path. Before the fix that path went on to its §3a
    /// checks and its own mint, with no durable-token check.
    #[tokio::test]
    async fn a_session_token_cannot_reseat_an_owner_axis_group() -> anyhow::Result<()> {
        use crate::server::rider_auth::ActorContext;
        use axum::body::to_bytes;

        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let keypair = state.agent.identity().agent_keypair();
        let local = local_hex(&state);
        let subject = "ab".repeat(32);
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?;
        let mut info = GroupInfo::with_policy(
            "adr0109-reseat-owner-axis".to_string(),
            String::new(),
            state.agent.agent_id(),
            "1533".repeat(16),
            x0x::groups::GroupPolicy {
                discoverability: x0x::groups::GroupDiscoverability::Hidden,
                admission: x0x::groups::GroupAdmission::InviteOnly,
                confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
                ..x0x::groups::GroupPolicy::default()
            },
        );
        info.add_member(
            subject.clone(),
            x0x::groups::GroupRole::Member,
            Some(local.clone()),
            None,
        );
        info.seal_commit(keypair, 1_000)?;
        info.remove_member(&subject, Some(local.clone()));
        info.seal_commit(keypair, 2_000)?;
        let basis = serde_json::json!({
            "kind": "removal", "revision": info.state_revision, "state_hash": info.state_hash,
        });
        // The owner axis is set after the seals, which would otherwise
        // need certificate evidence.
        info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
        let key = info.mls_group_id.clone();
        let stable = info.stable_group_id().to_string();
        state.named_groups.write().await.insert(key.clone(), info);

        let reseat = |durable: bool| {
            let request: ReseatRequest = serde_json::from_value(serde_json::json!({
                "reason": "forked while partitioned", "basis": basis,
            }))
            .expect("request decodes");
            reseat_group_member(
                State(Arc::clone(&state)),
                axum::extract::Extension(ActorContext::Owner { durable }),
                Path((key.clone(), subject.clone())),
                Json(request),
            )
        };
        let response = reseat(false).await.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("durable API token")),
            "{body}"
        );
        assert!(
            sidecar_snapshot(&state, &stable)
                .await
                .is_none_or(|body| body.issued_reseats.is_empty()),
            "a refused session re-seat records no authorisation"
        );
        // The durable token passes the fence and meets the §3a checks.
        let response = reseat(true).await.into_response();
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// A SignedPublic group that this node created, with `subject` seated
    /// and then removed by this node. Returns the key, the record and the
    /// `Removal` basis of the subject's removal.
    async fn removed_subject_group(
        state: &Arc<AppState>,
        subject: &str,
        owner: Option<x0x::identity::UserId>,
    ) -> anyhow::Result<(String, GroupInfo, serde_json::Value)> {
        let keypair = state.agent.identity().agent_keypair();
        let local = local_hex(state);
        let mut info = GroupInfo::with_policy(
            "adr0109-reseat-rc22".to_string(),
            String::new(),
            state.agent.agent_id(),
            "2222".repeat(16),
            x0x::groups::GroupPolicy {
                discoverability: x0x::groups::GroupDiscoverability::Hidden,
                admission: x0x::groups::GroupAdmission::InviteOnly,
                confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
                ..x0x::groups::GroupPolicy::default()
            },
        );
        info.add_member(
            subject.to_string(),
            x0x::groups::GroupRole::Member,
            Some(local.clone()),
            None,
        );
        info.seal_commit(keypair, 1_000)?;
        info.remove_member(subject, Some(local));
        info.seal_commit(keypair, 2_000)?;
        let basis = serde_json::json!({
            "kind": "removal", "revision": info.state_revision, "state_hash": info.state_hash,
        });
        // The owner axis is set after the seals, which would otherwise
        // need certificate evidence.
        if let Some(owner) = owner {
            info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner);
        }
        let key = info.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        Ok((key, info, basis))
    }

    /// #1533 rc22 (ZCode MAJOR-2), ADR 0109 §3 and §3a: a second route
    /// call for the same subject replaces its authorisation, and the
    /// replaced authorisation's invite is revoked first, durably. A join
    /// with the old invite then fails invite consumption, so the replaced
    /// pairing never reaches a seal. Before the fix the old invite stayed
    /// consumable, and its seal found no paired authorisation and sealed
    /// an ordinary add. Inert.
    #[tokio::test]
    async fn a_replaced_reseat_authorisation_loses_its_invite() -> anyhow::Result<()> {
        use crate::server::rider_auth::ActorContext;

        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let subject = "ab".repeat(32);
        let (key, info, basis) = removed_subject_group(&state, &subject, None).await?;
        let stable = info.stable_group_id().to_string();
        let reseat = || {
            let request: ReseatRequest = serde_json::from_value(serde_json::json!({
                "reason": "forked while partitioned", "basis": basis,
            }))
            .expect("request decodes");
            reseat_group_member(
                State(Arc::clone(&state)),
                axum::extract::Extension(ActorContext::Owner { durable: true }),
                Path((key.clone(), subject.clone())),
                Json(request),
            )
        };
        let paired = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            let stable = stable.clone();
            async move {
                sidecar_snapshot(&state, &stable)
                    .await
                    .map(|body| {
                        body.issued_reseats
                            .iter()
                            .map(|issued| issued.authorisation.fields.invite_secret_hash.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            }
        };
        let live_secrets = |state: &Arc<AppState>| {
            let state = Arc::clone(state);
            let key = key.clone();
            async move {
                state
                    .named_groups
                    .read()
                    .await
                    .get(&key)
                    .map(|info| {
                        info.issued_invites
                            .iter()
                            .filter(|(_, record)| record.consumed_by.is_none())
                            .map(|(secret, _)| secret.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            }
        };

        assert_eq!(reseat().await.into_response().status(), StatusCode::OK);
        let first = live_secrets(&state).await;
        assert_eq!(first.len(), 1, "one re-seat invite");
        assert_eq!(
            paired(&state).await,
            vec![s3::invite_secret_hash(&first[0])]
        );

        assert_eq!(reseat().await.into_response().status(), StatusCode::OK);
        let second = live_secrets(&state).await;
        assert_eq!(second.len(), 1, "the replaced invite is revoked");
        assert_ne!(second[0], first[0]);
        assert_eq!(
            paired(&state).await,
            vec![s3::invite_secret_hash(&second[0])],
            "one authorisation per (group, subject)"
        );
        // A join with the replaced invite fails before any seal.
        let mut probe = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("group"))?;
        assert_eq!(
            probe.consume_issued_invite(
                &first[0],
                &subject,
                x0x::groups::GroupRole::Member,
                now_ms(),
                now_ms()
            ),
            Err("invite_secret_unknown")
        );
        // The revocation is durable.
        let on_disk = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(!on_disk.issued_invites.contains_key(&first[0]));
        assert!(on_disk.issued_invites.contains_key(&second[0]));
        Ok(())
    }

    /// Call the re-seat route with the durable owner token. Returns the
    /// status and the JSON body.
    async fn call_reseat(
        state: &Arc<AppState>,
        key: &str,
        subject: &str,
        basis: &serde_json::Value,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let request: ReseatRequest = serde_json::from_value(serde_json::json!({
            "reason": "forked while partitioned", "basis": basis,
        }))?;
        let response = reseat_group_member(
            State(Arc::clone(state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path((key.to_string(), subject.to_string())),
            Json(request),
        )
        .await
        .into_response();
        let status = response.status();
        let body =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await?)?;
        Ok((status, body))
    }

    /// The issued re-seats' invite secret hashes, and the unconsumed live
    /// invite secrets, of one group.
    async fn reseat_pairing(
        state: &AppState,
        key: &str,
        stable: &str,
    ) -> (Vec<String>, Vec<String>) {
        let paired = sidecar_snapshot(state, stable)
            .await
            .map(|body| {
                body.issued_reseats
                    .iter()
                    .map(|issued| issued.authorisation.fields.invite_secret_hash.clone())
                    .collect()
            })
            .unwrap_or_default();
        let live = state
            .named_groups
            .read()
            .await
            .get(key)
            .map(|info| {
                info.issued_invites
                    .iter()
                    .filter(|(_, record)| record.consumed_by.is_none())
                    .map(|(secret, _)| secret.clone())
                    .collect()
            })
            .unwrap_or_default();
        (paired, live)
    }

    /// #1533 review (ZCode), ADR 0109 §3a route checks and D170: on an
    /// owner-axis group where this node holds no owner USER key, a
    /// promoted admin re-seats only a removal that it committed itself. A
    /// `Removal` basis that another admin committed is refused
    /// `reseat_removal_not_own`, and nothing is signed, stored or minted.
    /// Control: this admin's own removal passes that check and meets the
    /// next one, the capability floor (`reseat_receiver_upgrade_required`
    /// names the other admin, which has no current verified advert). Inert.
    #[tokio::test]
    async fn a_promoted_admin_reseats_only_its_own_removal() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        assert!(state.agent.identity().user_keypair().is_none());
        let keypair = state.agent.identity().agent_keypair();
        let local = local_hex(&state);
        let peer = x0x::identity::AgentKeypair::generate()?;
        let peer_hex = hex::encode(peer.agent_id().as_bytes());
        let theirs = "ab".repeat(32);
        let mine = "cd".repeat(32);
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?;
        let mut info = GroupInfo::with_policy(
            "adr0109-reseat-d170".to_string(),
            String::new(),
            state.agent.agent_id(),
            "1700".repeat(16),
            x0x::groups::GroupPolicy {
                discoverability: x0x::groups::GroupDiscoverability::Hidden,
                admission: x0x::groups::GroupAdmission::InviteOnly,
                confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
                ..x0x::groups::GroupPolicy::default()
            },
        );
        for (member, role) in [
            (&peer_hex, x0x::groups::GroupRole::Admin),
            (&theirs, x0x::groups::GroupRole::Member),
            (&mine, x0x::groups::GroupRole::Member),
        ] {
            info.add_member(member.clone(), role, Some(local.clone()), None);
        }
        info.seal_commit(keypair, 1_000)?;
        // The other admin removes `theirs`; this node removes `mine`.
        info.remove_member(&theirs, Some(peer_hex.clone()));
        info.seal_commit(&peer, 2_000)?;
        let theirs_basis = serde_json::json!({
            "kind": "removal", "revision": info.state_revision, "state_hash": info.state_hash,
        });
        info.remove_member(&mine, Some(local.clone()));
        info.seal_commit(keypair, 3_000)?;
        let mine_basis = serde_json::json!({
            "kind": "removal", "revision": info.state_revision, "state_hash": info.state_hash,
        });
        // The owner axis is set after the seals, which would otherwise
        // need certificate evidence.
        info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner.user_id());
        let key = info.mls_group_id.clone();
        let stable = info.stable_group_id().to_string();
        state.named_groups.write().await.insert(key.clone(), info);

        let (status, body) = call_reseat(&state, &key, &theirs, &theirs_basis).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "reseat_removal_not_own", "{body}");
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            (Vec::new(), Vec::new()),
            "no authorisation stored and no invite minted"
        );
        assert!(!tokio::fs::try_exists(sidecar_path(&state, &stable)).await?);

        let (status, body) = call_reseat(&state, &key, &mine, &mine_basis).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "reseat_receiver_upgrade_required", "{body}");
        assert_eq!(body["detail"]["members"], serde_json::json!([peer_hex]));
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            (Vec::new(), Vec::new())
        );
        Ok(())
    }

    /// ADR 0109 §3 route checks: a contained admin (`admin_contained`) and
    /// a banned or revoked subject (`subject_banned_or_revoked`) are
    /// refused, and nothing is stored or minted. Control: the same call on
    /// the clean record succeeds. Inert.
    #[tokio::test]
    async fn the_reseat_route_refuses_a_contained_admin_and_a_banned_or_revoked_subject(
    ) -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let subject_kp = x0x::identity::AgentKeypair::generate()?;
        let subject = hex::encode(subject_kp.agent_id().as_bytes());
        let (key, info, basis) = removed_subject_group(&state, &subject, None).await?;
        let stable = info.stable_group_id().to_string();
        let set_live = |live: GroupInfo| {
            let state = Arc::clone(&state);
            let key = key.clone();
            async move {
                state.named_groups.write().await.insert(key, live);
            }
        };

        let mut contained = info.clone();
        contained.fork_quarantine = Some(original_marker(&state, &info));
        set_live(contained).await;
        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "admin_contained", "{body}");
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            (Vec::new(), Vec::new())
        );

        let mut banned = info.clone();
        banned.ban_member(&subject, Some(local));
        set_live(banned).await;
        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "subject_banned_or_revoked", "{body}");
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            (Vec::new(), Vec::new())
        );

        // Control: the clean record.
        set_live(info).await;
        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let issued = reseat_pairing(&state, &key, &stable).await;
        assert_eq!(issued.1.len(), 1);

        // The subject's agent is revoked (a self-signed revocation).
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Agent(subject_kp.agent_id()),
            subject_kp.public_key(),
            subject_kp.secret_key(),
            now_ms() / 1000,
            None,
        )?;
        state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)?;
        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "subject_banned_or_revoked", "{body}");
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            issued,
            "the refusal changes nothing"
        );
        Ok(())
    }

    /// An owner-axis group with no owner key here, and `subject` removed
    /// by this node with its owner certificate kept on the seat: the
    /// promoted-admin path reaches its mint. Returns the key, the stable
    /// ID and the basis.
    async fn promoted_reseat_group(
        state: &Arc<AppState>,
        subject: &x0x::identity::AgentKeypair,
    ) -> anyhow::Result<(String, String, serde_json::Value)> {
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?;
        let subject_hex = hex::encode(subject.agent_id().as_bytes());
        let cert = x0x::identity::AgentCertificate::issue(&owner, subject)?;
        let (key, info, basis) =
            removed_subject_group(state, &subject_hex, Some(owner.user_id())).await?;
        state
            .named_groups
            .write()
            .await
            .get_mut(&key)
            .ok_or_else(|| anyhow::anyhow!("group"))?
            .set_member_certificate(&subject_hex, cert)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok((key, info.stable_group_id().to_string(), basis))
    }

    /// #1533 review (ZCode minor), ADR 0109 §3 "one per `(group,
    /// subject)`": on the promoted-admin path the replaced invite is
    /// revoked in the same roster write as the new invite. So a 503 from
    /// the mint (`invite_sign_failed` or `invite_too_large`, or
    /// `not_durable` when the roster write is refused) leaves the previous authorisation and its invite intact and
    /// consumable. Before the fix the revocation was durable first, and the
    /// 503 left the subject with neither. A later success still revokes the
    /// replaced invite, durably. Inert.
    #[tokio::test]
    async fn a_failed_promoted_reseat_mint_keeps_the_previous_pairing() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let subject_kp = x0x::identity::AgentKeypair::generate()?;
        let subject = hex::encode(subject_kp.agent_id().as_bytes());
        let (key, stable, basis) = promoted_reseat_group(&state, &subject_kp).await?;

        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (paired, live) = reseat_pairing(&state, &key, &stable).await;
        assert_eq!(live.len(), 1, "one re-seat invite");
        assert_eq!(paired, vec![s3::invite_secret_hash(&live[0])]);
        let first = (paired, live);

        // `invite_sign_failed`: a group name over the invite limit does not
        // sign (the same pre-write error path as `invite_too_large`).
        let name = state
            .named_groups
            .read()
            .await
            .get(&key)
            .map(|info| info.name.clone())
            .unwrap_or_default();
        if let Some(info) = state.named_groups.write().await.get_mut(&key) {
            info.name = "n".repeat(x0x::groups::invite::INVITE_MAX_GROUP_NAME + 1);
        }
        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["reason"], "invite_sign_failed", "{body}");
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            first,
            "the previous authorisation and its invite are intact"
        );
        if let Some(info) = state.named_groups.write().await.get_mut(&key) {
            info.name = name;
        }

        // `not_durable`: the roster write is refused (`NotReplaced`).
        let seq = std::sync::atomic::Ordering::SeqCst;
        state.named_groups_save_fault.store(1, seq);
        let refused = call_reseat(&state, &key, &subject, &basis).await;
        state.named_groups_save_fault.store(0, seq);
        let (status, body) = refused?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["reason"], "not_durable", "{body}");
        assert_eq!(reseat_pairing(&state, &key, &stable).await, first);
        // An owner-axis record is kept in the Home-suite store.
        let on_disk = legacy_entry(&state.home_suite_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("home-suite entry"))?;
        assert!(on_disk.issued_invites.contains_key(&first.1[0]));

        // A success replaces the pairing and revokes the old invite durably.
        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (paired, live) = reseat_pairing(&state, &key, &stable).await;
        assert_eq!(live.len(), 1, "the replaced invite is revoked");
        assert_ne!(live[0], first.1[0]);
        assert_eq!(paired, vec![s3::invite_secret_hash(&live[0])]);
        // An owner-axis record is kept in the Home-suite store.
        let on_disk = legacy_entry(&state.home_suite_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("home-suite entry"))?;
        assert!(!on_disk.issued_invites.contains_key(&first.1[0]));
        assert!(on_disk.issued_invites.contains_key(&live[0]));
        Ok(())
    }

    /// Mark the group's sidecar as at fault (§4): every `update_sidecar`
    /// write is then not durable, which is the injected authorisation
    /// store failure of the #1648 tests.
    async fn fail_the_authorisation_store(state: &Arc<AppState>, stable: &str) {
        state
            .group_recovery
            .inner
            .lock()
            .await
            .sidecar_status
            .insert(
                stable.to_string(),
                SidecarFault::Unavailable {
                    file: s3::sidecar_file_name(stable),
                    cause: "injected store failure (#1648)".to_string(),
                },
            );
    }

    /// #1648 (follow-up to the #1533 review, finding 1), owner path: the
    /// authorisation store fails after `mint_invite_transaction` made the
    /// invite durable. The route answers 503 and the minted invite is
    /// revoked, in memory and on disk, because no authorisation pairs
    /// with it. Before the fix the revoke set came only from
    /// `issued_reseats`, which never recorded it, and the orphan stayed
    /// consumable as an ordinary 1-hour admin invite until expiry. Inert.
    #[tokio::test]
    async fn a_failed_authorisation_store_revokes_the_minted_invite() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let subject = "ab".repeat(32);
        let (key, info, basis) = removed_subject_group(&state, &subject, None).await?;
        let stable = info.stable_group_id().to_string();
        fail_the_authorisation_store(&state, &stable).await;

        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error"], "the re-seat authorisation is not durable");
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            (Vec::new(), Vec::new()),
            "no authorisation recorded and no live invite"
        );
        // The revocation is durable: no live secret stays on disk.
        let on_disk = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(on_disk.issued_invites.is_empty(), "no orphan on disk");
        Ok(())
    }

    /// #1648 on the promoted-admin path (§3a): the same store failure,
    /// after `mint_reseat_invite`'s durable roster write recorded the
    /// invite as an ordinary issued invite. The failed store revokes it
    /// there too. Inert.
    #[tokio::test]
    async fn a_failed_authorisation_store_revokes_the_promoted_mint() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let subject_kp = x0x::identity::AgentKeypair::generate()?;
        let subject = hex::encode(subject_kp.agent_id().as_bytes());
        let (key, stable, basis) = promoted_reseat_group(&state, &subject_kp).await?;
        fail_the_authorisation_store(&state, &stable).await;

        let (status, body) = call_reseat(&state, &key, &subject, &basis).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(
            reseat_pairing(&state, &key, &stable).await,
            (Vec::new(), Vec::new()),
            "no authorisation recorded and no live invite"
        );
        // The revocation is durable: an owner-axis record is kept in the
        // Home-suite store.
        let on_disk = legacy_entry(&state.home_suite_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("home-suite entry"))?;
        assert!(on_disk.issued_invites.is_empty(), "no orphan on disk");
        Ok(())
    }

    /// ADR 0109 §4 (D120): after a damaged sidecar is quarantined and
    /// rebuilt, `GET /groups/:id/recovery` on an Active admin shows
    /// `issued_reseats_lost: true`, since the unconsumed authorisations
    /// were in the lost file. Controls: `false` before the rebuild, and
    /// `false` when this node holds no admin seat. Inert.
    #[tokio::test]
    async fn a_rebuilt_admin_sidecar_reports_issued_reseats_lost() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let subject = "ab".repeat(32);
        let (key, info, _basis) = removed_subject_group(&state, &subject, None).await?;
        let stable = info.stable_group_id().to_string();
        let recovery = || {
            let state = Arc::clone(&state);
            let key = key.clone();
            async move {
                let response = get_group_recovery(State(state), Path(key))
                    .await
                    .into_response();
                assert_eq!(response.status(), StatusCode::OK);
                let body: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 1 << 20).await?,
                )?;
                anyhow::Ok(body)
            }
        };
        assert_eq!(recovery().await?["issued_reseats_lost"], false);

        let path = sidecar_path(&state, &stable);
        tokio::fs::create_dir_all(sidecar_dir(&state)).await?;
        tokio::fs::write(&path, [b"JUNKJUNK".as_slice(), &[0u8; 56]].concat()).await?;
        load_sidecars(&state).await;
        resume_deferred_quarantine(&state).await;
        assert_eq!(
            sidecar_on_disk(&state, &stable).await?.rebuilt_from.len(),
            1
        );
        let body = recovery().await?;
        assert_eq!(body["issued_reseats_lost"], true, "{body}");
        assert_eq!(
            body["sidecar"]["rebuilt_from"].as_array().map(Vec::len),
            Some(1)
        );

        if let Some(live) = state.named_groups.write().await.get_mut(&key) {
            live.set_member_role(&local_hex(&state), x0x::groups::GroupRole::Member);
        }
        assert_eq!(recovery().await?["issued_reseats_lost"], false);
        Ok(())
    }

    /// ADR 0109 §4 "Rebuild source" (D147): a pre-Welcome joiner whose
    /// sidecar was rebuilt without its served chain, admin-armed and with
    /// no progress for `GATE_STALL`, shows `readmission_required {cause:
    /// local_state_lost}`. Controls: no rebuild, an Active seat, and a
    /// stall shorter than `GATE_STALL` each stay out of it. Inert.
    #[tokio::test]
    async fn a_rebuilt_pre_welcome_joiner_stalls_into_local_state_lost() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let now = Instant::now();
        state
            .group_recovery
            .inner
            .lock()
            .await
            .subjects
            .insert(stable.clone(), SubjectState::new(now, info.state_revision));
        let mut pre_welcome = info.clone();
        pre_welcome.remove_member(&local, None);
        assert!(update_sidecar(&state, &stable, move |body| body.active_ata = Some(ata)).await);
        assert!(armed_admin_ata(&state, &pre_welcome).await.is_some());

        // No rebuild: no loss, however long the stall.
        assert!(!local_state_lost(&state, &key, &pre_welcome, now + s3::GATE_STALL).await);
        assert!(update_sidecar(&state, &stable, |body| body.rebuilt_from.push([7; 16])).await);
        // An Active seat is not pre-Welcome.
        assert!(!local_state_lost(&state, &key, &info, now + s3::GATE_STALL).await);
        // The stall must reach `GATE_STALL`.
        assert!(!local_state_lost(&state, &key, &pre_welcome, now).await);
        assert!(local_state_lost(&state, &key, &pre_welcome, now + s3::GATE_STALL).await);
        assert_eq!(
            view_of(&state, &stable).await,
            Some(SubjectView::Readmission {
                cause: "local_state_lost"
            })
        );
        let recovery = recovery_json(&state, &pre_welcome)
            .await
            .ok_or_else(|| anyhow::anyhow!("recovery object"))?;
        assert_eq!(recovery["state"], "readmission_required");
        assert_eq!(recovery["cause"], "local_state_lost");
        assert_eq!(recovery["exit"], "manual_remove_and_reinvite");
        Ok(())
    }

    /// #1533 rc22 (ZCode MAJOR-2), ADR 0109 §3a "never omits the mandate":
    /// at seal on a promoted admin (owner axis, no owner key here), a
    /// re-seat invite whose authorisation expired before the seal is
    /// refused with `reseat_invite_unpaired`; it is not sealed as an
    /// ordinary add with no mandate. An invite that no authorisation ever
    /// paired is not a re-seat. Inert.
    #[tokio::test]
    async fn a_reseat_invite_unpaired_at_seal_seals_nothing() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let keypair = state.agent.identity().agent_keypair();
        let local = local_hex(&state);
        let subject = "ab".repeat(32);
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?;
        let (_key, info, _basis) =
            removed_subject_group(&state, &subject, Some(owner.user_id())).await?;
        let stable = info.stable_group_id().to_string();
        let issue = |secret: &str, expires_at_ms: u64| -> anyhow::Result<IssuedReseatV1> {
            Ok(IssuedReseatV1 {
                authorisation: ReseatAuthorisation::sign(
                    ReseatAuthorisationFields {
                        group: stable.clone(),
                        subject: subject.clone(),
                        basis: ReseatBasis::Removal {
                            revision: info.state_revision,
                            state_hash: info.state_hash.clone(),
                        },
                        invite_secret_hash: s3::invite_secret_hash(secret),
                        invite_base_revision: info.state_revision,
                        invite_base_state_hash: info.state_hash.clone(),
                        signer: local.clone(),
                        reason_hash: s3::reason_hash("r"),
                        expires_at_ms,
                    },
                    keypair,
                )?,
                invite: String::new(),
                issued_at_ms: now_ms(),
            })
        };
        let seal = |secret: &'static str| {
            let state = Arc::clone(&state);
            let info = info.clone();
            let subject = subject.clone();
            async move {
                reseat_mandate_for_seat(
                    &state,
                    &info,
                    &info,
                    &subject,
                    secret,
                    1,
                    None,
                    x0x::groups::GroupRole::Member,
                )
                .await
            }
        };

        let expired = issue("expired-secret", now_ms().saturating_sub(1))?;
        assert!(
            update_sidecar(&state, &stable, move |body| body
                .issued_reseats
                .push(expired))
            .await
        );
        assert!(matches!(
            seal("expired-secret").await,
            ReseatSeal::Refused("reseat_invite_unpaired")
        ));
        // The prune keeps the expired entry long enough for that check.
        prune_admin_state(&state).await;
        assert!(matches!(
            seal("expired-secret").await,
            ReseatSeal::Refused("reseat_invite_unpaired")
        ));
        // Control: an invite no authorisation names is not a re-seat.
        assert!(matches!(
            seal("ordinary-secret").await,
            ReseatSeal::NotReseat
        ));
        // Control: a current pairing goes on to the §3a floor and bindings.
        let current = issue("current-secret", u64::MAX / 2)?;
        assert!(
            update_sidecar(&state, &stable, move |body| body
                .issued_reseats
                .push(current))
            .await
        );
        assert!(!matches!(
            seal("current-secret").await,
            ReseatSeal::NotReseat | ReseatSeal::Refused("reseat_invite_unpaired")
        ));
        Ok(())
    }

    /// #1533 rc22 (ZCode MAJOR-1), ADR 0109 §4 "Timing", H-S3-t (4):
    /// inside an uncommitted ADR 0094 trial S3 creates no sidecar and
    /// writes no placeholder. The node keeps today's state and shows
    /// `recovery_deferred {cause: host_commit_pending}`. After host commit
    /// the same arming writes the sidecar and the placeholder. Inert.
    #[tokio::test]
    async fn an_upgrade_trial_defers_s3_writes_until_host_commit() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        super::super::revocation_eviction::tests::write_upgrade_journal(
            &state.data_dir,
            "health_committed",
        )?;

        assert!(!arm_in_place(&state, &key, &info, ata.clone()).await);
        assert!(!tokio::fs::try_exists(sidecar_path(&state, &stable)).await?);
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&legacy), "no placeholder in a trial");
        let recovery = recovery_json(&state, &info)
            .await
            .ok_or_else(|| anyhow::anyhow!("recovery object"))?;
        assert_eq!(recovery["state"], "recovery_deferred");
        assert_eq!(recovery["cause"], HOST_COMMIT_PENDING);
        assert!(sidecar_creation_deferred(&state, &stable).await);

        super::super::revocation_eviction::tests::write_upgrade_journal(
            &state.data_dir,
            "host_committed",
        )?;
        assert!(!sidecar_creation_deferred(&state, &stable).await);
        assert!(arm_in_place(&state, &key, &info, ata).await);
        assert!(tokio::fs::try_exists(sidecar_path(&state, &stable)).await?);
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(s3::is_s3_placeholder(&legacy), "armed after host commit");
        Ok(())
    }

    /// #1533 rc22 (ZCode MAJOR-1), ADR 0109 §4: a sidecar already on disk
    /// was created after an earlier host commit, so a trial keeps it
    /// current; and the re-seat route signs, stores and mints nothing for
    /// a group with no sidecar before host commit. Inert.
    #[tokio::test]
    async fn an_upgrade_trial_keeps_existing_sidecars_and_refuses_new_reseats() -> anyhow::Result<()>
    {
        use crate::server::rider_auth::ActorContext;
        use axum::body::to_bytes;

        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (_key, held, ata) = armed_fixture(&state).await?;
        let held_stable = held.stable_group_id().to_string();
        assert!(
            update_sidecar(&state, &held_stable, move |body| body.active_ata =
                Some(ata))
            .await
        );
        let subject = "ab".repeat(32);
        let (key, info, basis) = removed_subject_group(&state, &subject, None).await?;
        let stable = info.stable_group_id().to_string();
        super::super::revocation_eviction::tests::write_upgrade_journal(
            &state.data_dir,
            "health_committed",
        )?;

        assert!(!sidecar_creation_deferred(&state, &held_stable).await);
        let before = sidecar_on_disk(&state, &held_stable).await?.generation;
        assert!(
            update_sidecar(&state, &held_stable, |_| {}).await,
            "an existing sidecar is kept current"
        );
        assert!(sidecar_on_disk(&state, &held_stable).await?.generation > before);
        assert!(sidecar_creation_deferred(&state, &stable).await);

        let request: ReseatRequest = serde_json::from_value(serde_json::json!({
            "reason": "forked while partitioned", "basis": basis,
        }))?;
        let response = reseat_group_member(
            State(Arc::clone(&state)),
            axum::extract::Extension(ActorContext::Owner { durable: true }),
            Path((key.clone(), subject.clone())),
            Json(request),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(body["reason"], "recovery_deferred");
        assert_eq!(body["detail"]["cause"], HOST_COMMIT_PENDING);
        assert!(!tokio::fs::try_exists(sidecar_path(&state, &stable)).await?);
        let live = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("group"))?;
        assert!(live.issued_invites.is_empty(), "no invite minted");
        Ok(())
    }

    /// #1533 rc22 (ZCode MAJOR-1), ADR 0109 §4 "Before host commit every
    /// file stays in place": a damaged sidecar found inside a trial is not
    /// quarantined. Its bytes stay, and the group shows
    /// `recovery_deferred {cause: host_commit_pending}`. After host commit
    /// the next tick quarantines and rebuilds it (D120). Inert.
    #[tokio::test]
    async fn a_damaged_sidecar_waits_for_host_commit_before_quarantine() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (_key, info, _ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let path = sidecar_path(&state, &stable);
        tokio::fs::create_dir_all(sidecar_dir(&state)).await?;
        let junk = [b"JUNKJUNK".as_slice(), &[0u8; 56]].concat();
        tokio::fs::write(&path, &junk).await?;
        super::super::revocation_eviction::tests::write_upgrade_journal(
            &state.data_dir,
            "health_committed",
        )?;

        load_sidecars(&state).await;
        assert_eq!(tokio::fs::read(&path).await?, junk, "kept in place");
        let recovery = recovery_json(&state, &info)
            .await
            .ok_or_else(|| anyhow::anyhow!("recovery object"))?;
        assert_eq!(recovery["state"], "recovery_deferred");
        assert_eq!(recovery["cause"], HOST_COMMIT_PENDING);
        resume_deferred_quarantine(&state).await;
        assert_eq!(tokio::fs::read(&path).await?, junk, "still in place");

        super::super::revocation_eviction::tests::write_upgrade_journal(
            &state.data_dir,
            "host_committed",
        )?;
        resume_deferred_quarantine(&state).await;
        let rebuilt = sidecar_on_disk(&state, &stable).await?;
        assert_eq!(rebuilt.rebuilt_from.len(), 1, "quarantined and rebuilt");
        assert!(!state
            .group_recovery
            .inner
            .lock()
            .await
            .sidecar_status
            .contains_key(&stable));
        Ok(())
    }

    /// A SignedPublic group with this node Active, durable on disk, and a
    /// `Prepared` re-seat journal for it (the journal is not yet written).
    async fn reseat_fixture(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(String, GroupInfo, ReseatJournalV1)> {
        let keypair = state.agent.identity().agent_keypair();
        let local = local_hex(state);
        let mut info = GroupInfo::with_policy(
            "adr0109-reseat-journal".to_string(),
            String::new(),
            state.agent.agent_id(),
            "2109".repeat(16),
            x0x::groups::GroupPolicy {
                discoverability: x0x::groups::GroupDiscoverability::Hidden,
                admission: x0x::groups::GroupAdmission::InviteOnly,
                confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
                ..x0x::groups::GroupPolicy::default()
            },
        );
        info.seal_commit(keypair, 1_000)?;
        assert!(info.has_active_member(&local));
        let key = info.mls_group_id.clone();
        // `persist_named_group_info` only replaces an existing entry; a new
        // group is inserted, then the roster is saved.
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let authorisation = ReseatAuthorisation::sign(
            ReseatAuthorisationFields {
                group: info.stable_group_id().to_string(),
                subject: local.clone(),
                basis: ReseatBasis::Removal {
                    revision: info.state_revision,
                    state_hash: info.state_hash.clone(),
                },
                invite_secret_hash: s3::invite_secret_hash("secret"),
                invite_base_revision: info.state_revision,
                invite_base_state_hash: info.state_hash.clone(),
                signer: local.clone(),
                reason_hash: s3::reason_hash("r"),
                expires_at_ms: u64::MAX / 2,
            },
            keypair,
        )?;
        let live_record = serde_json::to_vec(&info)?;
        let journal = ReseatJournalV1 {
            authorisation,
            invite: String::new(),
            record_digest: *blake3::hash(&live_record).as_bytes(),
            phase: ReseatPhase::Prepared,
            live_key: key.clone(),
            live_record,
            live_tree: None,
            started_at_ms: now_ms(),
        };
        Ok((key, info, journal))
    }

    async fn on_disk_keys(state: &AppState) -> anyhow::Result<Vec<String>> {
        let bytes = tokio::fs::read(&state.named_groups_path).await?;
        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&bytes)?;
        Ok(map.keys().cloned().collect())
    }

    async fn open_journal(state: &AppState, stable: &str) -> Option<ReseatJournalV1> {
        sidecar_snapshot(state, stable)
            .await
            .and_then(|body| body.reseat_journal)
    }

    async fn view_of(state: &AppState, stable: &str) -> Option<SubjectView> {
        state
            .group_recovery
            .inner
            .lock()
            .await
            .subjects
            .get(stable)
            .map(|subject| subject.view.clone())
    }

    /// Codex P1 (#1533 round 1): a re-seat preparation that stops after
    /// its journal must not lose the original record or close the journal
    /// before the rollback is durable. #1699: the preparation writes no
    /// roster (the original stays live; `open_staging` only opens the
    /// staging slot), so the failure is the step after the slot opens: the
    /// `Staging` mark. The journal stays `Prepared`, the staging is open,
    /// and the rollback's re-persist of the original meets the roster
    /// fault.
    #[tokio::test]
    async fn failed_reseat_preparation_keeps_the_journal_until_rollback_is_durable(
    ) -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        // Both injected roster-write outcomes: `NotReplaced` (1) keeps the
        // map; `ReplacedNotDurable` (3) leaves the journal as the copy.
        for fault in [1u8, 3u8] {
            let (key, info, journal) = reseat_fixture(&state).await?;
            let stable = info.stable_group_id().to_string();
            state
                .group_recovery
                .inner
                .lock()
                .await
                .staging_live
                .insert(stable.clone());
            state.named_groups_save_fault.store(fault, Ordering::SeqCst);
            let digest = journal.record_digest;
            // `prepare_reseat` up to its failed `Staging` mark: the
            // `Prepared` journal, then the open staging slot.
            assert!(
                update_sidecar(&state, &stable, |body| body.reseat_journal = Some(journal)).await
            );
            open_staging(&state, &key, &info).await;
            assert!(state.reseat_stagings.scope_for(&key).is_some());
            assert_eq!(
                state
                    .named_groups
                    .live_read()
                    .await
                    .get(&key)
                    .map(|record| record.state_hash.clone()),
                Some(info.state_hash.clone()),
                "fault {fault}: the original stays live"
            );
            let open = open_journal(&state, &stable).await;
            assert!(
                open.as_ref()
                    .is_some_and(|journal| journal.phase == ReseatPhase::Prepared),
                "fault {fault}: the journal (the original's only sure copy) stays open"
            );
            // The rollback cannot be durable while the fault holds: the
            // journal stays and the worker retries.
            rollback_reseat(&state, &stable, digest, "journal_not_durable").await;
            assert!(
                open_journal(&state, &stable).await.is_some(),
                "fault {fault}"
            );
            assert!(
                state.reseat_stagings.scope_for(&key).is_none(),
                "fault {fault}: the rollback closes the staging first"
            );
            state.named_groups_save_fault.store(0, Ordering::SeqCst);
            state
                .group_recovery
                .inner
                .lock()
                .await
                .staging_live
                .remove(&stable);
            // The worker's retry: a `Prepared` journal not being prepared in
            // this process rolls back.
            reseat_progress(&state).await;
            assert!(
                open_journal(&state, &stable).await.is_none(),
                "fault {fault}"
            );
            let live = state.named_groups.live_read().await.get(&key).cloned();
            assert_eq!(
                live.as_ref().map(|record| record.state_hash.clone()),
                Some(info.state_hash.clone()),
                "fault {fault}: the original record is live"
            );
            assert!(on_disk_keys(&state).await?.contains(&key), "fault {fault}");
            assert!(matches!(
                view_of(&state, &stable).await,
                Some(SubjectView::Reseat {
                    cause: "reseat_failed",
                    ..
                })
            ));
            let retired = sidecar_snapshot(&state, &stable)
                .await
                .map_or(0, |body| body.retired.len());
            assert_eq!(retired, 0, "a rollback retires nothing");
            state.group_recovery.inner.lock().await.subjects.clear();
        }
        Ok(())
    }

    /// Codex P1 (#1533 round 1): crash at each re-seat phase. Only a staged
    /// result bound to the journal swaps; the original forked record (live
    /// because the crash came before its move aside) never does.
    /// The live record of `key` is gone, durably (a crash of an older
    /// binary that moved the original aside before its staged join).
    async fn drop_live_record(state: &AppState, key: &str) -> bool {
        let key = key.to_string();
        state.treekem_groups.live_write().await.remove(&key);
        matches!(
            super::super::persist_named_groups_mutation(state, move |groups| {
                groups.remove(&key).is_some()
            })
            .await,
            Ok(super::super::AtomicWriteOutcome::Durable)
        )
    }

    #[tokio::test]
    async fn reseat_resume_at_each_phase_never_swaps_the_original() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let keypair = state.agent.identity().agent_keypair();
        let retired = |state: Arc<AppState>, stable: String| async move {
            sidecar_snapshot(&state, &stable)
                .await
                .map_or(0, |body| body.retired.len())
        };

        // 1. Crash after the journal, before the move: `Prepared`, the
        //    original is live and shows this node Active. Before the fix the
        //    resume closed the journal here as a successful re-seat.
        let (key, info, journal) = reseat_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(update_sidecar(&state, &stable, |body| body.reseat_journal = Some(journal)).await);
        resume_journals(&state).await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert_eq!(retired(Arc::clone(&state), stable.clone()).await, 0);
        assert!(matches!(
            view_of(&state, &stable).await,
            Some(SubjectView::Reseat {
                cause: "reseat_failed",
                ..
            })
        ));
        assert!(state.named_groups.read().await.contains_key(&key));
        state.group_recovery.inner.lock().await.subjects.clear();

        // 2. Crash after the move, before the phase write: `Prepared`, no
        //    live record. The record comes back from the journal.
        let (key, info, journal) = reseat_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(update_sidecar(&state, &stable, |body| body.reseat_journal = Some(journal)).await);
        assert!(drop_live_record(&state, &key).await);
        // #1533 review: the open journal keeps the original on disk.
        assert!(on_disk_keys(&state).await?.contains(&key));
        resume_journals(&state).await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert!(on_disk_keys(&state).await?.contains(&key));
        assert_eq!(
            state
                .named_groups
                .read()
                .await
                .get(&key)
                .map(|record| record.state_hash.clone()),
            Some(info.state_hash.clone())
        );
        assert_eq!(retired(Arc::clone(&state), stable.clone()).await, 0);
        state.group_recovery.inner.lock().await.subjects.clear();

        // 3. `Staging` with the original record under the key: a restart
        //    (the legacy files hold the original). Not a swap: the staged
        //    join is gone, so it rolls back and retires nothing (#1533).
        let (key, info, mut journal) = reseat_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        journal.phase = ReseatPhase::Staging;
        let reopen = journal.clone();
        assert!(update_sidecar(&state, &stable, |body| body.reseat_journal = Some(journal)).await);
        resume_journals(&state).await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert_eq!(retired(Arc::clone(&state), stable.clone()).await, 0);
        assert_eq!(
            state
                .named_groups
                .read()
                .await
                .get(&key)
                .map(|record| record.state_hash.clone()),
            Some(info.state_hash.clone())
        );
        assert!(update_sidecar(&state, &stable, |body| body.reseat_journal = Some(reopen)).await);

        // 4. `Staging` with a staged result sealed past the invite base and
        //    this node Active: the swap retires the original once.
        let mut staged = info.clone();
        staged.name = "staged".to_string();
        staged.seal_commit(keypair, 2_000)?;
        let staged_key = staged.mls_group_id.clone();
        state.reseat_stagings.open(&staged_key, &stable);
        state
            .named_groups
            .staging_write()
            .await
            .insert(staged_key.clone(), staged.clone());
        resume_journals(&state).await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert_eq!(retired(Arc::clone(&state), stable.clone()).await, 1);
        // The swap wrote the staged record to the legacy files.
        let on_disk = legacy_entry(&state.named_groups_path, &staged_key).await?;
        assert_eq!(
            on_disk.map(|record| record.state_hash),
            Some(staged.state_hash)
        );

        // 5. `Staging`, the in-memory stub lost in a restart: roll back.
        let (key, info, mut journal) = reseat_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        journal.phase = ReseatPhase::Staging;
        assert!(update_sidecar(&state, &stable, |body| body.reseat_journal = Some(journal)).await);
        assert!(drop_live_record(&state, &key).await);
        resume_journals(&state).await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert!(on_disk_keys(&state).await?.contains(&key));
        assert!(matches!(
            view_of(&state, &stable).await,
            Some(SubjectView::Reseat {
                cause: "reseat_failed",
                ..
            })
        ));
        Ok(())
    }

    /// #1533 review (Codex P1, re-seat containment), daemon level: with the
    /// journal open, a staged record written with no marker (Active) holds
    /// the original's, so the shared ADR 0066 entry gate, the before-effect
    /// re-check and the S3 containment check refuse as for the original.
    /// Inert (offline agent).
    #[tokio::test]
    async fn staged_reseat_gates_refuse_as_for_the_original() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let keypair = state.agent.identity().agent_keypair();
        let (key, mut info, mut journal) = reseat_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let staged = {
            let mut staged = info.clone();
            staged.seal_commit(keypair, 2_000)?;
            staged
        };
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: info.state_revision,
            state_hash: "sibling".to_string(),
            committed_by: local_hex(&state),
            observed_at_ms: 1,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        });
        journal.live_record = serde_json::to_vec(&info)?;
        journal.phase = ReseatPhase::Staging;
        assert!(update_sidecar(&state, &stable, |body| body.reseat_journal = Some(journal)).await);
        // #1699: the staged join writes in its staging slot.
        state.reseat_stagings.open(&key, &stable);
        let (write_key, record) = (key.clone(), staged);
        let outcome = in_staging(
            &state,
            &key,
            super::super::persist_named_groups_mutation(&state, move |groups| {
                groups.insert(write_key, record);
                true
            }),
        )
        .await?;
        assert_eq!(outcome, super::super::AtomicWriteOutcome::Durable);
        let staged = state
            .named_groups
            .staging_read()
            .await
            .get(&key)
            .cloned()
            .expect("the staged record is in the staging slot");
        assert_eq!(staged.fork_quarantine, info.fork_quarantine);
        assert!(super::super::reject_fork_quarantined(&state, &key, &staged).is_some());
        // The before-effect re-check of a step of the staged join reads
        // the staging slot.
        assert!(in_staging(
            &state,
            &key,
            super::super::reject_fork_quarantine_installed_before_effect(&state, &key, None),
        )
        .await
        .is_some());
        assert!(contained(&state, &staged).await);
        Ok(())
    }

    /// The marker of a contained original record in `state`.
    fn original_marker(state: &AppState, info: &GroupInfo) -> x0x::groups::ForkQuarantine {
        x0x::groups::ForkQuarantine {
            revision: info.state_revision,
            state_hash: "sibling".to_string(),
            committed_by: local_hex(state),
            observed_at_ms: 1,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        }
    }

    /// Run `fut` as a step of the staged join of `key` (#1699, ADR 0109 §3
    /// step 2): in its open staging, as `consume_reseat` and the inbound
    /// handlers run it. Its map writes land in the staging slot.
    async fn in_staging<F: std::future::Future>(state: &AppState, key: &str, fut: F) -> F::Output {
        assert!(
            state.reseat_stagings.scope_for(key).is_some(),
            "the staging of {key} is open"
        );
        state.reseat_stagings.run_in_staging_of(key, fut).await
    }

    /// A contained original (marker set, live and durable), its re-seat
    /// prepared through the production path (journal, open staging,
    /// `Staging`), and the staged join's seated record written by an
    /// ordinary roster write, in the staging, with no marker of its own.
    /// The original stays live (#1699). Returns the key, the original, its
    /// marker and the staged record as written.
    async fn staged_reseat(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(String, GroupInfo, x0x::groups::ForkQuarantine, GroupInfo)> {
        let keypair = state.agent.identity().agent_keypair();
        let (key, mut info, mut journal) = reseat_fixture(state).await?;
        let stable = info.stable_group_id().to_string();
        let marker = original_marker(state, &info);
        info.fork_quarantine = Some(marker.clone());
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        journal.live_record = serde_json::to_vec(&info)?;
        journal.record_digest = *blake3::hash(&journal.live_record).as_bytes();
        state
            .group_recovery
            .inner
            .lock()
            .await
            .staging_live
            .insert(stable.clone());
        assert_eq!(prepare_reseat(state, &key, &info, journal).await, Ok(()));
        let mut staged = info.clone();
        staged.fork_quarantine = None;
        staged.seal_commit(keypair, 2_000)?;
        let (write_key, record) = (key.clone(), staged.clone());
        let outcome = in_staging(
            state,
            &key,
            super::super::persist_named_groups_mutation(state, move |groups| {
                groups.insert(write_key, record);
                true
            }),
        )
        .await?;
        assert_eq!(outcome, super::super::AtomicWriteOutcome::Durable);
        assert_eq!(
            state
                .named_groups
                .live_read()
                .await
                .get(&key)
                .map(|record| record.state_hash.clone()),
            Some(info.state_hash.clone()),
            "the original stays live"
        );
        assert_eq!(
            state
                .named_groups
                .staging_read()
                .await
                .get(&key)
                .map(|record| record.state_hash.clone()),
            Some(staged.state_hash.clone()),
            "the staged record is in the staging slot"
        );
        Ok((key, info, marker, staged))
    }

    /// #1533 review (Codex P1, round 3): the staged record in the live map
    /// holds the original's marker from its first write until the swap.
    /// No clear lifts it before the swap, and the swap lifts it only with a
    /// durable roster write: a `ReplacedNotDurable` swap keeps the marker
    /// and the journal. Before the fix the staged record had no marker, so
    /// every background gate that reads the record admitted it. Inert.
    #[tokio::test]
    async fn a_staged_record_keeps_the_original_marker_until_a_durable_swap() -> anyhow::Result<()>
    {
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, _, marker, staged) = staged_reseat(&state).await?;
        let stable = staged.stable_group_id().to_string();
        // #1699: the staged record is in the staging slot; the live map
        // keeps the contained original until the swap.
        let staged_marker = |state: Arc<AppState>, key: String| async move {
            state
                .named_groups
                .staging_read()
                .await
                .get(&key)
                .and_then(|record| record.fork_quarantine.clone())
        };
        let live_marker = |state: Arc<AppState>, key: String| async move {
            state
                .named_groups
                .live_read()
                .await
                .get(&key)
                .and_then(|record| record.fork_quarantine.clone())
        };
        assert_eq!(
            staged_marker(Arc::clone(&state), key.clone()).await,
            Some(marker.clone()),
            "the staged record holds the original's marker"
        );
        assert_eq!(
            live_marker(Arc::clone(&state), key.clone()).await,
            Some(marker.clone()),
            "the original stays live and contained"
        );
        assert_eq!(
            crate::server::delegations::fork_quarantine_marker(&state, &stable).await,
            Some(marker.clone())
        );
        let in_slot = state.named_groups.staging_read().await.get(&key).cloned();
        assert!(contained(&state, &in_slot.expect("the staged record is in the slot")).await);
        // A clear before the swap (the manual clear, a mandate or adoption
        // clear, the S3 retirement) all pass the one clear gate: held, on
        // the staged record (a step of the staged join) and on the live
        // original.
        for staged_step in [true, false] {
            let clear_key = key.clone();
            let clear =
                super::super::persist_named_groups_quarantine_clear_gated(&state, move |groups| {
                    groups
                        .get_mut(&clear_key)
                        .map(|record| record.fork_quarantine = None)
                        .is_some()
                });
            let _ = if staged_step {
                in_staging(&state, &key, clear).await
            } else {
                clear.await
            };
            assert_eq!(
                staged_marker(Arc::clone(&state), key.clone()).await,
                Some(marker.clone()),
                "staged step {staged_step}: no clear lifts the staged marker before the swap"
            );
            assert_eq!(
                live_marker(Arc::clone(&state), key.clone()).await,
                Some(marker.clone()),
                "staged step {staged_step}: no clear lifts the live marker before the swap"
            );
        }
        // The swap's roster write is not durable: marker and journal stay.
        state.named_groups_save_fault.store(3, Ordering::SeqCst);
        swap_now_if_seated(&state, &stable).await;
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        assert_eq!(
            live_marker(Arc::clone(&state), key.clone()).await,
            Some(marker.clone()),
            "a swap that is not durable keeps the marker"
        );
        assert!(open_journal(&state, &stable).await.is_some());
        // A durable swap lifts it, on disk and in memory, and closes the
        // journal and the staging.
        swap_now_if_seated(&state, &stable).await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert_eq!(live_marker(Arc::clone(&state), key.clone()).await, None);
        assert_eq!(
            state
                .named_groups
                .live_read()
                .await
                .get(&key)
                .map(|record| record.state_hash.clone()),
            Some(staged.state_hash.clone()),
            "the staged record is live"
        );
        assert!(state.named_groups.staging_read().await.is_empty());
        assert!(state.reseat_stagings.scope_for(&key).is_none());
        let on_disk = legacy_entry(&state.named_groups_path, &key)
            .await?
            .expect("the swapped-in record is on disk");
        assert_eq!(on_disk.state_hash, staged.state_hash);
        assert!(on_disk.fork_quarantine.is_none());
        let retired = sidecar_snapshot(&state, &stable)
            .await
            .map_or(0, |body| body.retired.len());
        assert_eq!(retired, 1);
        Ok(())
    }

    /// #1533 rc13 (Codex P2 @c226d28e), ADR 0109 §3 step 3: a staged GSS
    /// join is Active on its `MemberAdded` before its `SecureShareDelivered`
    /// installs the shared secret. Until the share arrives the swap does
    /// not run: the original's containment stays and the journal stays
    /// open (a share that never arrives ends at the journal deadline, which
    /// rolls back). Before the fix the readiness check covered only the
    /// TreeKEM tree, so the keyless record swapped in. Inert.
    #[tokio::test]
    async fn a_gss_reseat_swaps_only_once_its_share_is_installed() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, _, marker, staged) = staged_reseat(&state).await?;
        let stable = staged.stable_group_id().to_string();
        let set_secret = |secret: Option<Vec<u8>>| {
            let state = Arc::clone(&state);
            let key = key.clone();
            async move {
                // The staged join's `MemberAdded` and `SecureShareDelivered`
                // applies: steps of the staged join, in its staging.
                let write_key = key.clone();
                let outcome = in_staging(
                    &state,
                    &key,
                    super::super::persist_named_groups_mutation(&state, move |groups| {
                        groups.get_mut(&write_key).is_some_and(|record| {
                            record.policy.confidentiality =
                                x0x::groups::GroupConfidentiality::MlsEncrypted;
                            record.secure_plane = x0x::mls::SecureGroupPlane::Gss;
                            record.shared_secret = secret;
                            true
                        })
                    }),
                )
                .await?;
                anyhow::ensure!(outcome == super::super::AtomicWriteOutcome::Durable);
                anyhow::Ok(())
            }
        };
        // Seated, encrypted, no share yet: no swap, however often it runs.
        set_secret(None).await?;
        for _ in 0..3 {
            assert!(!swap_if_seated(&state, &stable).await);
        }
        assert!(open_journal(&state, &stable).await.is_some());
        let in_slot = state.named_groups.staging_read().await.get(&key).cloned();
        let live = state.named_groups.live_read().await.get(&key).cloned();
        for (map, record) in [("staging slot", in_slot), ("live map", live)] {
            assert_eq!(
                record.and_then(|record| record.fork_quarantine),
                Some(marker.clone()),
                "{map}: the original's containment stays"
            );
        }
        // The delayed share arrives: the next tick swaps.
        set_secret(Some(vec![7; 32])).await?;
        assert!(swap_if_seated(&state, &stable).await);
        assert!(open_journal(&state, &stable).await.is_none());
        Ok(())
    }

    /// #1533 review (Codex P1): the swap and the rollback serialise on the
    /// group membership lock. A rollback holds that lock while it restores
    /// the original. A swap that starts then waits, and after the restore
    /// it sees the original and keeps its marker. Before the fix the swap
    /// read an unlocked snapshot of the staged record, then marked the
    /// journal `Swapping`, lifted the marker from every record of the group
    /// and closed the journal while the rollback ran, which released the
    /// containment with no re-seat. Inert.
    #[tokio::test]
    async fn a_swap_during_a_rollback_keeps_the_original_contained() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, marker, _) = staged_reseat(&state).await?;
        let stable = original.stable_group_id().to_string();
        let journal = open_journal(&state, &stable)
            .await
            .expect("the re-seat journal is open");
        // A rollback is in progress: it holds the membership lock.
        let lock = super::super::group_membership_lock(&state, &stable).await;
        let rollback_guard = lock.lock().await;
        let swap = {
            let state = Arc::clone(&state);
            let stable = stable.clone();
            tokio::spawn(async move { swap_now_if_seated(&state, &stable).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            open_journal(&state, &stable)
                .await
                .is_some_and(|open| open.phase == journal.phase),
            "the swap waits for the rollback"
        );
        // The rollback discards the staging (#1699) and restores the
        // original under the lock, then ends.
        assert!(discard_staging(&state, &key, &stable).await);
        assert!(restore_record_from_journal(&state, &stable, &key, &original, &journal).await);
        drop(rollback_guard);
        swap.await?;
        let current_marker = || async {
            state
                .named_groups
                .read()
                .await
                .get(&key)
                .and_then(|record| record.fork_quarantine.clone())
        };
        assert_eq!(current_marker().await, Some(marker.clone()));
        assert!(
            open_journal(&state, &stable).await.is_some(),
            "the swap does not close a journal whose original is back"
        );
        // The rollback closes the journal; the original stays contained,
        // in memory and on disk, and nothing is retired.
        rollback_reseat(&state, &stable, journal.record_digest, "test_rollback").await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert_eq!(current_marker().await, Some(marker.clone()));
        let on_disk = legacy_entry(&state.named_groups_path, &key)
            .await?
            .expect("the original is on disk");
        assert_eq!(on_disk.state_hash, original.state_hash);
        assert_eq!(on_disk.fork_quarantine, Some(marker));
        let retired = sidecar_snapshot(&state, &stable)
            .await
            .map_or(0, |body| body.retired.len());
        assert_eq!(retired, 0);
        Ok(())
    }

    /// #1533 review: a rollback decided on one journal never acts on
    /// another. After the swap closed the journal, a late rollback with
    /// the old journal's digest leaves the swapped-in record. Inert.
    #[tokio::test]
    async fn a_late_rollback_after_the_swap_keeps_the_swapped_record() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, _, staged) = staged_reseat(&state).await?;
        let stable = original.stable_group_id().to_string();
        let journal = open_journal(&state, &stable)
            .await
            .expect("the re-seat journal is open");
        swap_now_if_seated(&state, &stable).await;
        assert!(open_journal(&state, &stable).await.is_none());
        rollback_reseat(&state, &stable, journal.record_digest, "late_rollback").await;
        let live = state.named_groups.read().await.get(&key).cloned();
        assert_eq!(
            live.map(|record| record.state_hash),
            Some(staged.state_hash)
        );
        Ok(())
    }

    /// #1533 review (round 3): a crash with the staged record live and not
    /// swapped restarts with the contained original from the legacy files;
    /// the resume discards the staged join and keeps the original's
    /// marker. Inert.
    #[tokio::test]
    async fn a_crash_before_the_swap_restarts_with_the_original_contained() -> anyhow::Result<()> {
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, marker, _) = staged_reseat(&state).await?;
        let stable = info.stable_group_id().to_string();
        let restarted = super::super::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&state.agent),
        )
        .await?;
        drop(state);
        load_sidecars(&restarted).await;
        let live = restarted.named_groups.read().await.get(&key).cloned();
        assert_eq!(
            live.as_ref().map(|record| record.state_hash.clone()),
            Some(info.state_hash.clone()),
            "the legacy files hold the original, not the staged record"
        );
        assert_eq!(
            live.and_then(|record| record.fork_quarantine),
            Some(marker.clone())
        );
        resume_journals(&restarted).await;
        assert!(open_journal(&restarted, &stable).await.is_none());
        let live = restarted.named_groups.read().await.get(&key).cloned();
        assert_eq!(
            live.as_ref().map(|record| record.state_hash.clone()),
            Some(info.state_hash.clone())
        );
        assert_eq!(live.and_then(|record| record.fork_quarantine), Some(marker));
        let retired = sidecar_snapshot(&restarted, &stable)
            .await
            .map_or(0, |body| body.retired.len());
        assert_eq!(retired, 0, "the staged copy is discarded; nothing retires");
        Ok(())
    }

    /// #1533 review (round 3): the staged join still completes while its
    /// record holds the original's marker. Its Welcome install (the TreeKEM
    /// atomic persist) succeeds, also for a `next` that dropped the marker
    /// (an owner-mandate clear in the same `MemberAdded`): the hold gives it
    /// back, so the persist's marker check sees the same marker and does not
    /// refuse `fork_quarantined`. The 120 s poll does not hold the staged
    /// join (`held_join_state`). Inert.
    #[tokio::test]
    async fn the_staged_join_installs_its_tree_while_holding_the_marker() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let key = "e8".repeat(16);
        let group_id = hex::decode(&key)?;
        let creator = state.agent.agent_id();
        let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id);
        let tree = x0x::mls::TreeKemMlsGroup::create(group_id, creator, &seed)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let mut staged = GroupInfo::new("treekem".to_string(), String::new(), creator, key.clone());
        staged.migrate_from_v1();
        staged.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        staged.shared_secret = None;
        staged.secret_epoch = tree.epoch();
        staged.security_binding = Some(format!("treekem:epoch={}", tree.epoch()));
        staged.recompute_state_hash();
        let mut original = staged.clone();
        let marker = original_marker(&state, &original);
        original.fork_quarantine = Some(marker.clone());
        assert!(open_staging_journal_for_test(&state, &key, &original).await?);
        // #1567: the journal carries the original's tree, which the snapshot
        // file keeps while the join is staged.
        let original_tree = tree.to_snapshot_bytes()?;
        assert!(
            update_sidecar(&state, original.stable_group_id(), move |body| {
                if let Some(journal) = body.reseat_journal.as_mut() {
                    journal.live_tree = Some(original_tree);
                }
            })
            .await
        );
        // The stub install, then the Welcome install of a `next` with no
        // marker, in the open staging (#1699).
        state.reseat_stagings.open(&key, original.stable_group_id());
        let (write_key, record) = (key.clone(), staged.clone());
        let outcome = in_staging(
            &state,
            &key,
            super::super::persist_named_groups_mutation(&state, move |groups| {
                groups.insert(write_key, record);
                true
            }),
        )
        .await?;
        assert_eq!(outcome, super::super::AtomicWriteOutcome::Durable);
        in_staging(
            &state,
            &key,
            super::super::persist_treekem_and_named_groups_atomic_with_info(
                &state, &key, staged, &tree,
            ),
        )
        .await?;
        let in_slot = state
            .named_groups
            .staging_read()
            .await
            .get(&key)
            .cloned()
            .expect("the staged record is in the staging slot");
        assert_eq!(in_slot.fork_quarantine, Some(marker));
        assert!(in_staging(&state, &key, held_join_state(&state, &in_slot))
            .await
            .is_none());
        Ok(())
    }

    /// #1567 fixture: a contained TreeKEM original, durable with its tree
    /// (epoch 0), and an open `Staging` journal that holds both. Then the
    /// staged join's Welcome install under the same key: a new record (one
    /// commit later) and a different tree at the same epoch, so the startup
    /// re-bind (#457) would pair it with the original record. The Welcome
    /// install runs in the open staging; the original and its tree stay
    /// live (#1699). Returns the
    /// key, the original record, the original tree bytes, the staged
    /// record and the staged tree bytes.
    async fn staged_tree_fixture(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(String, GroupInfo, Vec<u8>, GroupInfo, Vec<u8>)> {
        staged_tree_fixture_with(state, "e9", None).await
    }

    /// [`staged_tree_fixture`] under `"<byte>" * 16`; with `owner` both
    /// records are on that owner's axis (`OwnerCertified`), so the roster
    /// files keep them in the Home-Suite sidecar.
    async fn staged_tree_fixture_with(
        state: &Arc<AppState>,
        byte: &str,
        owner: Option<x0x::identity::UserId>,
    ) -> anyhow::Result<(String, GroupInfo, Vec<u8>, GroupInfo, Vec<u8>)> {
        let key = byte.repeat(16);
        let group_id = hex::decode(&key)?;
        let creator = state.agent.agent_id();
        let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id);
        let original_tree = x0x::mls::TreeKemMlsGroup::create(group_id.clone(), creator, &seed)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let staged_tree = x0x::mls::TreeKemMlsGroup::create(group_id, creator, &[0x67; 32])
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let mut original =
            GroupInfo::new("treekem".to_string(), String::new(), creator, key.clone());
        original.migrate_from_v1();
        original.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        original.shared_secret = None;
        original.secret_epoch = original_tree.epoch();
        original.security_binding = Some(format!("treekem:epoch={}", original_tree.epoch()));
        original.recompute_state_hash();
        let mut staged = original.clone();
        staged.seal_commit(state.agent.identity().agent_keypair(), 2_000)?;
        assert_eq!(staged.security_binding, original.security_binding);
        // The owner axis is set after the seal, which would otherwise need
        // certificate evidence.
        if let Some(owner) = owner {
            for info in [&mut original, &mut staged] {
                info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner);
            }
        }
        original.fork_quarantine = Some(original_marker(state, &original));
        // The original, durable with its tree, as before the re-seat.
        super::super::persist_treekem_and_named_groups_atomic_with_info(
            state,
            &key,
            original.clone(),
            &original_tree,
        )
        .await?;
        let original_bytes = original_tree.to_snapshot_bytes()?;
        state.treekem_groups.live_write().await.insert(
            key.clone(),
            Arc::new(tokio::sync::Mutex::new(original_tree)),
        );
        assert!(open_staging_journal_for_test(state, &key, &original).await?);
        let journal_tree = original_bytes.clone();
        assert!(
            update_sidecar(state, original.stable_group_id(), move |body| {
                if let Some(journal) = body.reseat_journal.as_mut() {
                    journal.live_tree = Some(journal_tree);
                }
            })
            .await
        );
        // #1699: the staging opens (the original and its tree stay live),
        // then the staged join's Welcome install runs in it.
        open_staging(state, &key, &original).await;
        let staged_bytes = staged_tree.to_snapshot_bytes()?;
        in_staging(state, &key, async {
            super::super::persist_treekem_and_named_groups_atomic_with_info(
                state,
                &key,
                staged.clone(),
                &staged_tree,
            )
            .await?;
            state
                .treekem_groups
                .write()
                .await
                .insert(key.clone(), Arc::new(tokio::sync::Mutex::new(staged_tree)));
            anyhow::Ok(())
        })
        .await?;
        assert_live_original_and_staged(state, &key, &original, &staged).await;
        Ok((key, original, original_bytes, staged, staged_bytes))
    }

    /// The memory layout of a staged re-seat before its swap (#1699): the
    /// live map holds `original` (with its tree when it has one), the
    /// staging slot holds `staged` and its tree.
    async fn assert_live_original_and_staged(
        state: &AppState,
        key: &str,
        original: &GroupInfo,
        staged: &GroupInfo,
    ) {
        let hash = |record: Option<&GroupInfo>| record.map(|record| record.state_hash.clone());
        assert_eq!(
            hash(state.named_groups.live_read().await.get(key)),
            Some(original.state_hash.clone()),
            "the original stays live"
        );
        assert_eq!(
            hash(state.named_groups.staging_read().await.get(key)),
            Some(staged.state_hash.clone()),
            "the staged record is in the staging slot"
        );
        assert!(
            state.treekem_groups.staging_read().await.contains_key(key),
            "the staged tree is in the staging slot"
        );
    }

    /// The envelope in `<key>.snap` on disk.
    async fn snapshot_on_disk(
        state: &AppState,
        key: &str,
    ) -> anyhow::Result<super::super::TreeKemSnapshotEnvelope> {
        let bytes =
            tokio::fs::read(super::super::treekem_snapshot_path(&state.treekem_dir, key)).await?;
        super::super::decode_treekem_snapshot_envelope(&bytes)?
            .ok_or_else(|| anyhow::anyhow!("unbound snapshot"))
    }

    /// #1567, ADR 0109 §3 steps 2 and 3: while a re-seat join is staged,
    /// the snapshot file keeps the original's tree, bound to the original
    /// record, as the roster files keep the original record. A restart (or
    /// a released binary) loads that pair. Before the fix the staged
    /// join's Welcome install wrote its own tree to `<key>.snap` beside the
    /// original record; at the same epoch the startup re-bind paired them.
    /// The swap then puts the staged tree on disk with the staged record.
    /// Inert: an offline agent.
    #[tokio::test]
    async fn a_staged_reseat_keeps_the_originals_tree_on_disk_until_the_swap() -> anyhow::Result<()>
    {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, staged, staged_tree) =
            staged_tree_fixture(&state).await?;
        let stable = original.stable_group_id().to_string();
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(legacy.state_hash, original.state_hash, "roster overlay");
        let envelope = snapshot_on_disk(&state, &key).await?;
        assert_eq!(
            (envelope.state_revision, &envelope.state_hash),
            (original.state_revision, &original.state_hash),
            "the snapshot stays bound to the original record"
        );
        assert!(
            envelope.snapshot == original_tree,
            "the snapshot file keeps the original's tree while staged"
        );
        // A restart (or a released binary) on these files pairs the
        // original record with the original's tree.
        let roster = HashMap::from([(key.clone(), legacy)]);
        let restored =
            super::super::restore_treekem_groups(&roster, state.agent.as_ref(), &state.treekem_dir)
                .await;
        let tree = restored
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("the original tree restores"))?;
        assert!(tree.lock().await.to_snapshot_bytes()? == original_tree);

        // The swap: the staged record and its tree reach disk together.
        let journal = sidecar_snapshot(&state, &stable)
            .await
            .and_then(|body| body.reseat_journal)
            .ok_or_else(|| anyhow::anyhow!("open journal"))?;
        assert!(swap_staged_tree(&state, &stable, &journal, &key, StagedSource::Staging).await);
        let envelope = snapshot_on_disk(&state, &key).await?;
        assert_eq!(
            (envelope.state_revision, &envelope.state_hash),
            (staged.state_revision, &staged.state_hash)
        );
        assert!(
            envelope.snapshot == staged_tree,
            "the swap writes the staged tree"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(legacy.state_hash, staged.state_hash);
        Ok(())
    }

    /// #1645 (Codex P1 on #1683), ADR 0109 §3 step 3: the swap's tree
    /// write replaces the Home-Suite sidecar before its commit point. When
    /// a later write fails, the swap puts both roster stores back with the
    /// original's snapshot, so a restart loads the original record beside
    /// the original's tree. Before the fix the sidecar kept the staged
    /// record, and at the same epoch the startup re-bind (#457) paired it
    /// with the original's tree. Inert: an offline agent.
    #[tokio::test]
    async fn a_failed_owner_certified_swap_restarts_on_the_original_pair() -> anyhow::Result<()> {
        use super::super::{set_save_fault, SaveFault};
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        let (key, original, original_tree, staged, staged_tree) =
            staged_tree_fixture_with(&state, "eb", Some(owner)).await?;
        let stable = original.stable_group_id().to_string();
        let sidecar_before = tokio::fs::read(&state.home_suite_groups_path).await?;
        let named_before = tokio::fs::read(&state.named_groups_path).await?;

        let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
        assert!(swap_if_seated(&state, &stable).await, "retried next tick");
        drop(fault);
        assert_eq!(
            open_journal(&state, &stable).await.map(|j| j.phase),
            Some(ReseatPhase::Staging)
        );
        assert!(
            tokio::fs::read(&state.home_suite_groups_path).await? == sidecar_before,
            "the sidecar is back"
        );
        assert!(tokio::fs::read(&state.named_groups_path).await? == named_before);

        // A restart on these files: the original record from the sidecar,
        // paired with the original's tree.
        let roster = super::super::load_named_groups_merged(
            &state.named_groups_path,
            &state.home_suite_groups_path,
        )
        .await?;
        let loaded = roster
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("the group loads"))?;
        assert!(loaded.policy.admission.owner_certified_user_id().is_some());
        assert_eq!(
            loaded.state_hash, original.state_hash,
            "the original record"
        );
        let restored =
            super::super::restore_treekem_groups(&roster, state.agent.as_ref(), &state.treekem_dir)
                .await;
        let tree = restored
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("the original tree restores"))?;
        assert!(tree.lock().await.to_snapshot_bytes()? == original_tree);

        // The retry swaps: the staged record and its tree reach disk.
        assert!(swap_if_seated(&state, &stable).await);
        assert!(open_journal(&state, &stable).await.is_none(), "swapped");
        let roster = super::super::load_named_groups_merged(
            &state.named_groups_path,
            &state.home_suite_groups_path,
        )
        .await?;
        let loaded = roster
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("the group loads"))?;
        assert_eq!(loaded.state_hash, staged.state_hash);
        assert!(snapshot_on_disk(&state, &key).await?.snapshot == staged_tree);
        Ok(())
    }

    /// A restart on `dir`, in `x0xd`'s start order: replay the TreeKEM
    /// transaction journals, load the rosters and the trees, then load the
    /// S3 sidecars and resume the re-seat journals.
    async fn restart_at(
        state: Arc<AppState>,
        dir: &std::path::Path,
    ) -> anyhow::Result<Arc<AppState>> {
        let agent = Arc::clone(&state.agent);
        super::super::recover_treekem_named_journals(
            &state.named_groups_path,
            &state.home_suite_groups_path,
            &state.treekem_dir,
        )
        .await?;
        drop(state);
        let restarted = super::super::tests::secure_endpoint_test_state_at(dir, agent).await?;
        let roster = restarted.named_groups.read().await.clone();
        let trees = super::super::restore_treekem_groups(
            &roster,
            restarted.agent.as_ref(),
            &restarted.treekem_dir,
        )
        .await;
        restarted.treekem_groups.write().await.extend(trees);
        load_sidecars(&restarted).await;
        resume_journals(&restarted).await;
        Ok(restarted)
    }

    /// The record that `state` holds under `key`, its tree when loaded,
    /// and the tree on disk are one pair: the original record with the
    /// original's tree, or the staged record with the staged tree. Returns
    /// whether it is the staged pair.
    async fn holds_a_matching_pair(
        state: &AppState,
        key: &str,
        original: &GroupInfo,
        original_tree: &[u8],
        staged: &GroupInfo,
        staged_tree: &[u8],
    ) -> anyhow::Result<bool> {
        let record = state
            .named_groups
            .read()
            .await
            .get(key)
            .map(|record| record.state_hash.clone())
            .ok_or_else(|| anyhow::anyhow!("the group loads"))?;
        // The fixture's staged tree is not from this agent's seed, so a
        // restart cannot load it: then only the files are compared.
        let tree = match state.treekem_groups.read().await.get(key).cloned() {
            Some(tree) => Some(tree.lock().await.to_snapshot_bytes()?),
            None => None,
        };
        let on_disk = snapshot_on_disk(state, key).await?;
        let staged_pair = record == staged.state_hash;
        let (want_tree, want_hash) = if staged_pair {
            (staged_tree, &staged.state_hash)
        } else {
            anyhow::ensure!(record == original.state_hash, "an unknown record loads");
            (original_tree, &original.state_hash)
        };
        anyhow::ensure!(
            tree.as_deref().is_none_or(|tree| tree == want_tree) && on_disk.snapshot == want_tree,
            "torn pair: the {} record loads with another tree",
            if staged_pair { "staged" } else { "original" }
        );
        anyhow::ensure!(
            &on_disk.state_hash == want_hash,
            "the snapshot binds another record"
        );
        Ok(staged_pair)
    }

    /// #1645 (Codex P1 on #1683 and #1645), ADR 0109 §3: a crash part way
    /// through a failed swap's rollback restarts on a matching pair. The
    /// swap's transaction journals stay until the original's files are
    /// all back, so the restart replays the staged record with its tree
    /// and the `Swapping` journal swaps them in. Before the fix the
    /// journals were gone: after the snapshot restore the sidecar held the
    /// staged record beside the original's tree, and at the same epoch the
    /// startup re-bind (#457) paired them. Inert: an offline agent.
    #[tokio::test]
    async fn an_interrupted_swap_rollback_restarts_on_a_matching_pair() -> anyhow::Result<()> {
        use super::super::{set_save_fault, SaveFault};
        for (byte, stop) in [
            ("ec", SwapRollbackStop::AfterSnapshot),
            ("ed", SwapRollbackStop::AfterSidecar),
        ] {
            let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
            let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
            let (key, original, original_tree, staged, staged_tree) =
                staged_tree_fixture_with(&state, byte, Some(owner)).await?;
            let stable = original.stable_group_id().to_string();
            state.group_recovery.inner.lock().await.swap_rollback_stop = Some(stop);
            let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
            assert!(swap_if_seated(&state, &stable).await, "{stop:?}");
            drop(fault);
            assert_eq!(
                open_journal(&state, &stable).await.map(|j| j.phase),
                Some(ReseatPhase::Swapping),
                "{stop:?}"
            );
            let journal = super::super::treekem_journal_path(&state.treekem_dir, &key);
            assert!(
                tokio::fs::try_exists(&journal).await?,
                "{stop:?}: the transaction journal stays"
            );
            let restarted = restart_at(state, dir.path()).await?;
            let staged_pair = holds_a_matching_pair(
                &restarted,
                &key,
                &original,
                &original_tree,
                &staged,
                &staged_tree,
            )
            .await?;
            assert!(staged_pair, "{stop:?}: the restart replays the staged pair");
            assert_eq!(
                open_journal(&restarted, &stable).await.map(|j| j.phase),
                Some(ReseatPhase::Swapping),
                "{stop:?}: the swap resumes from its phase"
            );
        }
        Ok(())
    }

    /// #1645 (Codex P1 on #1645 and #1683), ADR 0109 §3: the original's
    /// files are back after a failed swap and the durable `Staging` write
    /// fails. Then another whole-roster save runs, and the node restarts.
    /// The restart loads the original record with the original's tree and
    /// rolls back. Before the fix the journals were gone and memory kept
    /// `Swapping`, so that save wrote the staged record beside the
    /// restored original tree: a torn pair. Inert: an offline agent.
    #[tokio::test]
    async fn a_failed_phase_reset_then_a_roster_save_restarts_on_the_original_pair(
    ) -> anyhow::Result<()> {
        use super::super::{set_save_fault, SaveFault};
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        let (key, original, original_tree, staged, staged_tree) =
            staged_tree_fixture_with(&state, "e9", Some(owner)).await?;
        let stable = original.stable_group_id().to_string();
        state.group_recovery.inner.lock().await.swap_rollback_stop =
            Some(SwapRollbackStop::PhaseWriteFails);
        let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
        assert!(swap_if_seated(&state, &stable).await, "retried next tick");
        drop(fault);
        state.group_recovery.inner.lock().await.swap_rollback_stop = None;
        assert_eq!(
            sidecar_on_disk(&state, &stable)
                .await?
                .reseat_journal
                .map(|journal| journal.phase),
            Some(ReseatPhase::Swapping),
            "the phase reset is not durable"
        );
        assert_eq!(
            open_journal(&state, &stable)
                .await
                .map(|journal| journal.phase),
            Some(ReseatPhase::Staging),
            "memory is back to `Staging`: the covers apply"
        );

        // Another whole-roster save, as for any other group.
        let outcome = super::super::persist_named_groups_mutation(&state, |_| true).await?;
        assert_eq!(outcome, super::super::AtomicWriteOutcome::Durable);
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(
            legacy.state_hash, original.state_hash,
            "the original record stays"
        );

        let restarted = restart_at(state, dir.path()).await?;
        let staged_pair = holds_a_matching_pair(
            &restarted,
            &key,
            &original,
            &original_tree,
            &staged,
            &staged_tree,
        )
        .await?;
        assert!(!staged_pair, "the restart loads the original pair");
        assert!(
            open_journal(&restarted, &stable).await.is_none(),
            "the restart rolls back"
        );
        Ok(())
    }

    /// #1645 (Codex P1, round 4), ADR 0109 §3: the swap's TreeKEM write
    /// stops before its commit point (the legacy journal write fails), and
    /// the snapshot restore would fail too. No live file changed, so the
    /// swap ends at once: memory goes back to `Staging` and no journal is
    /// left. A later whole-roster save keeps the original record, and a
    /// restart loads the original pair; in process the next tick swaps.
    /// Before the fix the swap tried the file restore, which failed, so
    /// memory kept `Swapping` (covers off) with no transaction journal: the
    /// roster save wrote the staged record beside the original's tree, and
    /// the restart paired them. Inert: an offline agent.
    #[tokio::test]
    async fn a_swap_stopped_before_its_commit_point_ends_on_the_original_pair() -> anyhow::Result<()>
    {
        use super::super::{set_save_fault, SaveFault};
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        for (byte, retry) in [("e7", false), ("e6", true)] {
            let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
            let (key, original, original_tree, staged, staged_tree) =
                staged_tree_fixture_with(&state, byte, Some(owner)).await?;
            let stable = original.stable_group_id().to_string();
            state.group_recovery.inner.lock().await.swap_rollback_stop =
                Some(SwapRollbackStop::SnapshotRestoreFails);
            let fault = set_save_fault(&state, SaveFault::JournalWriteFails);
            assert!(swap_if_seated(&state, &stable).await, "retried next tick");
            drop(fault);
            state.group_recovery.inner.lock().await.swap_rollback_stop = None;
            assert_eq!(
                open_journal(&state, &stable)
                    .await
                    .map(|journal| journal.phase),
                Some(ReseatPhase::Staging),
                "retry {retry}: memory is back to `Staging`: the covers apply"
            );
            let journal = super::super::treekem_journal_path(&state.treekem_dir, &key);
            let hsjournal = super::super::treekem_home_suite_journal_path(&state.treekem_dir, &key);
            assert!(
                !tokio::fs::try_exists(&journal).await?,
                "retry {retry}: no TreeKEM journal"
            );
            assert!(
                !tokio::fs::try_exists(&hsjournal).await?,
                "retry {retry}: no orphan Home-Suite journal"
            );

            if retry {
                assert!(swap_if_seated(&state, &stable).await, "the retry swaps");
                assert!(
                    holds_a_matching_pair(
                        &state,
                        &key,
                        &original,
                        &original_tree,
                        &staged,
                        &staged_tree
                    )
                    .await?,
                    "the retry holds the staged pair"
                );
                assert!(open_journal(&state, &stable).await.is_none(), "swapped");
                continue;
            }

            // Another whole-roster save, as for any other group.
            let outcome = super::super::persist_named_groups_mutation(&state, |_| true).await?;
            assert_eq!(outcome, super::super::AtomicWriteOutcome::Durable);
            let legacy = legacy_entry(&state.named_groups_path, &key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
            assert_eq!(
                legacy.state_hash, original.state_hash,
                "the original record stays"
            );

            let restarted = restart_at(state, dir.path()).await?;
            let staged_pair = holds_a_matching_pair(
                &restarted,
                &key,
                &original,
                &original_tree,
                &staged,
                &staged_tree,
            )
            .await?;
            assert!(!staged_pair, "the restart loads the original pair");
        }
        Ok(())
    }

    /// #1645 (Codex P1): a Home-Suite restore that fails is not ignored.
    /// The swap keeps its transaction journals and `Swapping`, so a crash
    /// restarts on the staged pair, and in process the next tick retries
    /// the swap. Before the fix the failure was logged, the journals were
    /// gone and the journal went back to `Staging`: the sidecar kept the
    /// staged record beside the original's tree. Inert.
    #[tokio::test]
    async fn a_failed_home_suite_restore_keeps_the_swap_recoverable() -> anyhow::Result<()> {
        use super::super::{set_save_fault, SaveFault};
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        for crash in [true, false] {
            let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
            let byte = if crash { "ee" } else { "ef" };
            let (key, original, original_tree, staged, staged_tree) =
                staged_tree_fixture_with(&state, byte, Some(owner)).await?;
            let stable = original.stable_group_id().to_string();
            state.group_recovery.inner.lock().await.swap_rollback_stop =
                Some(SwapRollbackStop::SidecarRestoreFails);
            let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
            assert!(swap_if_seated(&state, &stable).await);
            drop(fault);
            assert_eq!(
                open_journal(&state, &stable).await.map(|j| j.phase),
                Some(ReseatPhase::Swapping)
            );
            let journal = super::super::treekem_journal_path(&state.treekem_dir, &key);
            assert!(tokio::fs::try_exists(&journal).await?);
            let state = if crash {
                restart_at(state, dir.path()).await?
            } else {
                state.group_recovery.inner.lock().await.swap_rollback_stop = None;
                assert!(swap_if_seated(&state, &stable).await, "the retry swaps");
                state
            };
            assert!(
                holds_a_matching_pair(
                    &state,
                    &key,
                    &original,
                    &original_tree,
                    &staged,
                    &staged_tree
                )
                .await?,
                "crash {crash}: the staged pair"
            );
            if !crash {
                assert!(open_journal(&state, &stable).await.is_none(), "swapped");
            }
        }
        Ok(())
    }

    /// #1645 round 5 (Codex P1), ADR 0109 §3: a failed swap puts the
    /// original's snapshot back, but the Home-Suite restore fails. The swap
    /// keeps its transaction journals and refuses roster writes. A metadata
    /// save of the same group is refused, and it does not discard the
    /// swap's journals, so a restart replays the staged pair. Before the
    /// fix the save's rebind cleanup deleted both journals, and the restart
    /// paired the staged record with the original's tree. Inert.
    #[tokio::test]
    async fn a_refused_metadata_save_keeps_a_failed_swaps_journals() -> anyhow::Result<()> {
        use super::super::{set_save_fault, SaveFault};
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, staged, staged_tree) =
            staged_tree_fixture_with(&state, "e2", Some(owner)).await?;
        let stable = original.stable_group_id().to_string();
        state.group_recovery.inner.lock().await.swap_rollback_stop =
            Some(SwapRollbackStop::SidecarRestoreFails);
        let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
        assert!(swap_if_seated(&state, &stable).await);
        drop(fault);
        assert_eq!(
            open_journal(&state, &stable).await.map(|j| j.phase),
            Some(ReseatPhase::Swapping),
            "the swap stays recoverable"
        );
        let journal = super::super::treekem_journal_path(&state.treekem_dir, &key);
        let hsjournal = super::super::treekem_home_suite_journal_path(&state.treekem_dir, &key);
        assert!(tokio::fs::try_exists(&journal).await?, "TreeKEM journal");
        assert!(
            tokio::fs::try_exists(&hsjournal).await?,
            "Home-Suite journal"
        );

        // A metadata save of the same group: refused, journals kept.
        let mut next = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the live record"))?;
        // A changed name and a later revision. Not sealed: the owner axis
        // needs certificate evidence to seal.
        next.name = "metadata save during a failed swap".to_string();
        next.state_revision += 1;
        next.recompute_state_hash();
        assert!(
            super::super::persist_named_group_info(&state, &key, next)
                .await
                .is_err(),
            "the metadata save is refused"
        );
        assert!(
            tokio::fs::try_exists(&journal).await?,
            "the TreeKEM journal stays"
        );
        assert!(
            tokio::fs::try_exists(&hsjournal).await?,
            "the Home-Suite journal stays"
        );

        let restarted = restart_at(state, dir.path()).await?;
        assert!(
            holds_a_matching_pair(
                &restarted,
                &key,
                &original,
                &original_tree,
                &staged,
                &staged_tree,
            )
            .await?,
            "the restart replays the staged pair"
        );
        assert_eq!(
            open_journal(&restarted, &stable).await.map(|j| j.phase),
            Some(ReseatPhase::Swapping),
            "the swap resumes from its phase"
        );
        Ok(())
    }

    /// #1645 round 5 (audit R1), ADR 0109 §3: a failed swap puts the
    /// original's snapshot back, but the Home-Suite restore fails. The swap
    /// keeps its transaction journals and refuses roster writes. A local
    /// delete of the same group is refused before its journal removal, so
    /// the group and both journals stay, and a restart replays the staged
    /// pair. Before the fix the delete removed both journals first, then
    /// its absence persist was refused, and the restart lost the staged
    /// pair. Inert.
    #[tokio::test]
    async fn a_refused_delete_keeps_a_failed_swaps_journals() -> anyhow::Result<()> {
        use super::super::{set_save_fault, SaveFault};
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, staged, staged_tree) =
            staged_tree_fixture_with(&state, "d9", Some(owner)).await?;
        let stable = original.stable_group_id().to_string();
        state.group_recovery.inner.lock().await.swap_rollback_stop =
            Some(SwapRollbackStop::SidecarRestoreFails);
        let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
        assert!(swap_if_seated(&state, &stable).await);
        drop(fault);
        assert_eq!(
            open_journal(&state, &stable).await.map(|j| j.phase),
            Some(ReseatPhase::Swapping),
            "the swap stays recoverable"
        );
        let journal = super::super::treekem_journal_path(&state.treekem_dir, &key);
        let hsjournal = super::super::treekem_home_suite_journal_path(&state.treekem_dir, &key);
        assert!(tokio::fs::try_exists(&journal).await?, "TreeKEM journal");
        assert!(
            tokio::fs::try_exists(&hsjournal).await?,
            "Home-Suite journal"
        );

        // A local delete of the same group: refused, journals kept.
        assert!(
            !super::super::drop_local_named_group_state(
                &state,
                &key,
                Some(stable.as_str()),
                "test delete during failed swap",
            )
            .await,
            "the delete is refused"
        );
        assert!(
            tokio::fs::try_exists(&journal).await?,
            "the TreeKEM journal stays"
        );
        assert!(
            tokio::fs::try_exists(&hsjournal).await?,
            "the Home-Suite journal stays"
        );
        assert!(
            state.named_groups.read().await.contains_key(&key),
            "the group stays in the roster"
        );

        let restarted = restart_at(state, dir.path()).await?;
        assert!(
            holds_a_matching_pair(
                &restarted,
                &key,
                &original,
                &original_tree,
                &staged,
                &staged_tree,
            )
            .await?,
            "the restart replays the staged pair"
        );
        assert_eq!(
            open_journal(&restarted, &stable).await.map(|j| j.phase),
            Some(ReseatPhase::Swapping),
            "the swap resumes from its phase"
        );
        Ok(())
    }

    /// #1645 (round 4 audit), ADR 0109 §3: the swap's tree write fails
    /// past its commit point and the snapshot restore fails too. Until the
    /// files are back, every other whole-roster write is refused, so the
    /// transaction journals stay valid. A crash then replays the staged
    /// pair. In process, the next tick puts the files back, lifts the
    /// refusal and swaps. Before the fix a later roster save wrote the
    /// staged record (a newer revision) beside the original's tree; the
    /// startup replay dropped the journals as stale, and the restart
    /// paired the staged record with the original's tree. Inert: an
    /// offline agent.
    #[tokio::test]
    async fn a_failed_swap_restore_refuses_roster_writes_until_the_files_are_back(
    ) -> anyhow::Result<()> {
        use super::super::{set_save_fault, SaveFault};
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        for (byte, crash) in [("e5", true), ("e4", false)] {
            let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
            let (key, original, original_tree, staged, staged_tree) =
                staged_tree_fixture_with(&state, byte, Some(owner)).await?;
            let stable = original.stable_group_id().to_string();
            state.group_recovery.inner.lock().await.swap_rollback_stop =
                Some(SwapRollbackStop::SnapshotRestoreFails);
            let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
            assert!(swap_if_seated(&state, &stable).await, "crash {crash}");
            drop(fault);
            assert_eq!(
                open_journal(&state, &stable).await.map(|j| j.phase),
                Some(ReseatPhase::Swapping),
                "crash {crash}: the swap stays recoverable"
            );
            let journal = super::super::treekem_journal_path(&state.treekem_dir, &key);
            assert!(
                tokio::fs::try_exists(&journal).await?,
                "crash {crash}: the transaction journal stays"
            );

            // Another whole-roster save, as for any other group: refused.
            let named_before = tokio::fs::read(&state.named_groups_path).await?;
            assert!(
                super::super::persist_named_groups_mutation(&state, |_| true)
                    .await
                    .is_err(),
                "crash {crash}: the roster write is refused"
            );
            assert!(
                tokio::fs::read(&state.named_groups_path).await? == named_before,
                "crash {crash}: named_groups.json is unchanged"
            );

            if crash {
                let restarted = restart_at(state, dir.path()).await?;
                assert!(
                    holds_a_matching_pair(
                        &restarted,
                        &key,
                        &original,
                        &original_tree,
                        &staged,
                        &staged_tree,
                    )
                    .await?,
                    "the restart replays the staged pair"
                );
                assert_eq!(
                    open_journal(&restarted, &stable).await.map(|j| j.phase),
                    Some(ReseatPhase::Swapping),
                    "the swap resumes from its phase"
                );
                continue;
            }

            // The next tick puts the files back, lifts the refusal and
            // swaps in the same call.
            state.group_recovery.inner.lock().await.swap_rollback_stop = None;
            assert!(swap_if_seated(&state, &stable).await, "the retry swaps");
            assert!(open_journal(&state, &stable).await.is_none(), "swapped");
            let outcome = super::super::persist_named_groups_mutation(&state, |_| true).await?;
            assert_eq!(
                outcome,
                super::super::AtomicWriteOutcome::Durable,
                "the refusal is lifted"
            );
            assert!(
                holds_a_matching_pair(
                    &state,
                    &key,
                    &original,
                    &original_tree,
                    &staged,
                    &staged_tree
                )
                .await?,
                "the staged pair"
            );
            let restarted = restart_at(state, dir.path()).await?;
            assert!(
                holds_a_matching_pair(
                    &restarted,
                    &key,
                    &original,
                    &original_tree,
                    &staged,
                    &staged_tree,
                )
                .await?,
                "the restart keeps the staged pair"
            );
            assert!(open_journal(&restarted, &stable).await.is_none());
        }
        Ok(())
    }

    /// #1645 (round 4 review), ADR 0109 §3: a retry of a `Swapping`
    /// journal (here after a restart) fails past its commit point. It puts
    /// no file back: the files it could read are not known to be a matching
    /// pair, and their tree can be older than the tree in memory (a rewound
    /// ratchet). Its journals stay and replay the staged pair, every other
    /// roster write is refused, and the next tick retries forward. Before
    /// the fix the retry wrote back the files it read before the write and
    /// discarded the journals. Inert: an offline agent.
    #[tokio::test]
    async fn a_failed_swapping_retry_keeps_its_journals_and_retries_forward() -> anyhow::Result<()>
    {
        use super::super::{set_save_fault, SaveFault};
        let owner = x0x::identity::UserKeypair::from_seed(&[0x5E; 32])?.user_id();
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, staged, staged_tree) =
            staged_tree_fixture_with(&state, "e3", Some(owner)).await?;
        let stable = original.stable_group_id().to_string();
        // Reach a `Swapping` journal on the staged pair: a failed swap, then
        // a restart that replays its journals.
        state.group_recovery.inner.lock().await.swap_rollback_stop =
            Some(SwapRollbackStop::SnapshotRestoreFails);
        let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
        assert!(swap_if_seated(&state, &stable).await);
        drop(fault);
        let state = restart_at(state, dir.path()).await?;
        assert_eq!(
            open_journal(&state, &stable).await.map(|j| j.phase),
            Some(ReseatPhase::Swapping)
        );

        // The fixture's staged tree has its own seed, which the startup
        // restore does not know: load it as the staged join holds it.
        let tree =
            x0x::mls::TreeKemMlsGroup::restore(&staged_tree, state.agent.agent_id(), &[0x67; 32])
                .map_err(|error| anyhow::anyhow!("{error}"))?;
        state
            .treekem_groups
            .write()
            .await
            .insert(key.clone(), Arc::new(tokio::sync::Mutex::new(tree)));

        // The retry fails past its commit point.
        let fault = set_save_fault(&state, SaveFault::NamedNotReplacedAfterSnapshot);
        assert!(swap_if_seated(&state, &stable).await, "retried next tick");
        drop(fault);
        assert_eq!(
            open_journal(&state, &stable).await.map(|j| j.phase),
            Some(ReseatPhase::Swapping),
            "the swap stays recoverable"
        );
        let journal = super::super::treekem_journal_path(&state.treekem_dir, &key);
        assert!(
            tokio::fs::try_exists(&journal).await?,
            "the retry's journals stay"
        );
        assert!(
            super::super::persist_named_groups_mutation(&state, |_| true)
                .await
                .is_err(),
            "another roster write is refused"
        );

        // The next tick retries forward and swaps.
        assert!(swap_if_seated(&state, &stable).await, "the retry swaps");
        assert!(open_journal(&state, &stable).await.is_none(), "swapped");
        assert_eq!(
            super::super::persist_named_groups_mutation(&state, |_| true).await?,
            super::super::AtomicWriteOutcome::Durable,
            "the refusal is lifted"
        );
        let restarted = restart_at(state, dir.path()).await?;
        assert!(
            holds_a_matching_pair(
                &restarted,
                &key,
                &original,
                &original_tree,
                &staged,
                &staged_tree,
            )
            .await?,
            "the restart keeps the staged pair"
        );
        assert!(open_journal(&restarted, &stable).await.is_none());
        Ok(())
    }

    /// #1567: a rolled-back staged re-seat leaves the original record and
    /// the original's tree paired on disk. Inert: an offline agent.
    #[tokio::test]
    async fn a_rolled_back_reseat_keeps_the_originals_tree_on_disk() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, _, _) = staged_tree_fixture(&state).await?;
        let stable = original.stable_group_id().to_string();
        let journal = sidecar_snapshot(&state, &stable)
            .await
            .and_then(|body| body.reseat_journal)
            .ok_or_else(|| anyhow::anyhow!("open journal"))?;
        rollback_reseat(&state, &stable, journal.record_digest, "test").await;
        assert!(sidecar_snapshot(&state, &stable)
            .await
            .and_then(|body| body.reseat_journal)
            .is_none());
        let envelope = snapshot_on_disk(&state, &key).await?;
        assert_eq!(envelope.state_hash, original.state_hash);
        assert!(envelope.snapshot == original_tree);
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(legacy.state_hash, original.state_hash);
        Ok(())
    }

    /// #1567 fixture: a contained TreeKEM original with no tree and no
    /// snapshot file (the #871 gate-only, pre-Welcome joiner), durable, and
    /// an open `Staging` journal with no `live_tree`. Then the open staging
    /// and, in it, the staged join's stub install and its Welcome install
    /// under the same key: a new record (one commit later) and its tree.
    /// The original stays live (#1699). Returns the
    /// key, the original record, the staged record and the staged tree
    /// bytes.
    async fn treeless_staged_fixture(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(String, GroupInfo, GroupInfo, Vec<u8>)> {
        let key = "ea".repeat(16);
        let group_id = hex::decode(&key)?;
        let creator = state.agent.agent_id();
        let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id);
        let staged_tree = x0x::mls::TreeKemMlsGroup::create(group_id, creator, &seed)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let mut original =
            GroupInfo::new("treekem".to_string(), String::new(), creator, key.clone());
        original.migrate_from_v1();
        original.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
        original.shared_secret = None;
        original.secret_epoch = staged_tree.epoch();
        original.security_binding = Some(format!("treekem:epoch={}", staged_tree.epoch()));
        original.recompute_state_hash();
        let mut staged = original.clone();
        staged.seal_commit(state.agent.identity().agent_keypair(), 2_000)?;
        original.fork_quarantine = Some(original_marker(state, &original));
        // The original, durable with no tree, as before the re-seat.
        let (write_key, record) = (key.clone(), original.clone());
        let outcome = super::super::persist_named_groups_mutation(state, move |groups| {
            groups.insert(write_key, record);
            true
        })
        .await?;
        assert_eq!(outcome, super::super::AtomicWriteOutcome::Durable);
        assert!(!snapshot_exists(state, &key).await?);
        assert!(open_staging_journal_for_test(state, &key, &original).await?);
        // #1699: the staging opens (the original stays live), then the
        // staged join's stub and Welcome installs run in it.
        open_staging(state, &key, &original).await;
        let staged_bytes = staged_tree.to_snapshot_bytes()?;
        in_staging(state, &key, async {
            let (write_key, record) = (key.clone(), staged.clone());
            super::super::persist_named_groups_mutation(state, move |groups| {
                groups.insert(write_key, record);
                true
            })
            .await?;
            super::super::persist_treekem_and_named_groups_atomic_with_info(
                state,
                &key,
                staged.clone(),
                &staged_tree,
            )
            .await?;
            state
                .treekem_groups
                .write()
                .await
                .insert(key.clone(), Arc::new(tokio::sync::Mutex::new(staged_tree)));
            anyhow::Ok(())
        })
        .await?;
        assert_live_original_and_staged(state, &key, &original, &staged).await;
        assert!(
            !state.treekem_groups.live_read().await.contains_key(&key),
            "the original has no tree"
        );
        Ok((key, original, staged, staged_bytes))
    }

    /// Whether `<key>.snap` is on disk.
    async fn snapshot_exists(state: &AppState, key: &str) -> anyhow::Result<bool> {
        Ok(
            tokio::fs::try_exists(super::super::treekem_snapshot_path(&state.treekem_dir, key))
                .await?,
        )
    }

    /// #1567 (ZCode on b9e87bb), ADR 0109 §3 and H-S3-c / H-S3-d8: a
    /// re-seat whose original has no tree and no snapshot file completes,
    /// and the node ends Active with keys. While the join is staged, its
    /// Welcome install succeeds and `<key>.snap` stays absent, as the
    /// original had none, so a restart (or a released binary) finds the
    /// original record and no tree. The swap then writes the staged record
    /// and its tree. With b9e87bb's cover the Welcome install failed (no
    /// snapshot to keep), so this re-seat always rolled back. Inert: an
    /// offline agent.
    #[tokio::test]
    async fn a_treeless_originals_reseat_completes_active_with_keys() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, staged, staged_tree) = treeless_staged_fixture(&state).await?;
        let stable = original.stable_group_id().to_string();
        assert!(
            !snapshot_exists(&state, &key).await?,
            "the snapshot file stays absent while the join is staged"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(legacy.state_hash, original.state_hash, "roster overlay");

        assert!(swap_if_seated(&state, &stable).await);
        assert!(open_journal(&state, &stable).await.is_none(), "swapped");
        let envelope = snapshot_on_disk(&state, &key).await?;
        assert_eq!(
            (envelope.state_revision, &envelope.state_hash),
            (staged.state_revision, &staged.state_hash)
        );
        assert!(
            envelope.snapshot == staged_tree,
            "the swap writes the staged tree"
        );
        let live = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the staged record is live"))?;
        assert_eq!(live.state_hash, staged.state_hash);
        assert!(live.fork_quarantine.is_none(), "the swap lifts the marker");
        assert!(live.has_active_member(&local_hex(&state)), "Active");
        assert!(
            state.treekem_groups.read().await.contains_key(&key),
            "with keys"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(legacy.state_hash, staged.state_hash);
        Ok(())
    }

    /// #1567: a rolled-back re-seat of an original with no snapshot file
    /// leaves no snapshot file behind. Inert: an offline agent.
    #[tokio::test]
    async fn a_rolled_back_treeless_reseat_leaves_no_snapshot() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, _, _) = treeless_staged_fixture(&state).await?;
        let stable = original.stable_group_id().to_string();
        let journal = open_journal(&state, &stable)
            .await
            .ok_or_else(|| anyhow::anyhow!("open journal"))?;
        rollback_reseat(&state, &stable, journal.record_digest, "test").await;
        assert!(open_journal(&state, &stable).await.is_none());
        assert!(!snapshot_exists(&state, &key).await?);
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(legacy.state_hash, original.state_hash);
        Ok(())
    }

    /// #1658 (PR #1645 follow-up): a swap whose tree write leaves the
    /// staged snapshot on disk but does not commit puts the original's
    /// snapshot state back (Keep: the original's tree; Absent: no file),
    /// sets the journal back to `Staging` and keeps the original record in
    /// the roster files. The next swap then completes. Inert: an offline
    /// agent.
    #[tokio::test]
    async fn a_failed_swap_tree_write_restores_the_originals_snapshot_state() -> anyhow::Result<()>
    {
        use super::super::{set_save_fault, SaveFault};
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, staged, staged_tree) =
            staged_tree_fixture(&state).await?;
        let (state2, _dir2) = super::super::tests::secure_endpoint_test_state().await?;
        let (key2, original2, staged2, staged_tree2) = treeless_staged_fixture(&state2).await?;
        for (state, key, original, staged, staged_tree, keep) in [
            (
                &state,
                &key,
                &original,
                &staged,
                &staged_tree,
                Some(&original_tree),
            ),
            (&state2, &key2, &original2, &staged2, &staged_tree2, None),
        ] {
            let stable = original.stable_group_id().to_string();
            let fault = set_save_fault(state, SaveFault::NamedNotReplacedAfterSnapshot);
            assert!(swap_if_seated(state, &stable).await, "retried next tick");
            let journal = open_journal(state, &stable)
                .await
                .ok_or_else(|| anyhow::anyhow!("the journal stays open"))?;
            assert_eq!(journal.phase, ReseatPhase::Staging);
            match keep {
                Some(original_tree) => {
                    let envelope = snapshot_on_disk(state, key).await?;
                    assert_eq!(envelope.state_hash, original.state_hash);
                    assert!(
                        envelope.snapshot == *original_tree,
                        "Keep: the original's tree is back"
                    );
                }
                None => assert!(!snapshot_exists(state, key).await?, "Absent: no file"),
            }
            let legacy = legacy_entry(&state.named_groups_path, key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
            assert_eq!(legacy.state_hash, original.state_hash);

            drop(fault);
            assert!(swap_if_seated(state, &stable).await);
            assert!(open_journal(state, &stable).await.is_none(), "swapped");
            let envelope = snapshot_on_disk(state, key).await?;
            assert_eq!(envelope.state_hash, staged.state_hash);
            assert!(
                envelope.snapshot == *staged_tree,
                "the retry writes the staged tree"
            );
            let legacy = legacy_entry(&state.named_groups_path, key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
            assert_eq!(legacy.state_hash, staged.state_hash);
        }
        Ok(())
    }

    /// `staged`, one sealed metadata commit later.
    fn staged_metadata_commit(state: &AppState, staged: &GroupInfo) -> anyhow::Result<GroupInfo> {
        let mut next = staged.clone();
        next.description = "staged metadata change".to_string();
        next.seal_commit(state.agent.identity().agent_keypair(), 3_000)?;
        Ok(next)
    }

    /// #1567 (ZCode on f9a11b3: the hook had no test): a metadata commit
    /// on the staged record runs the TreeKEM re-bind
    /// (`rebind_envelope_for`). While the join is staged, the re-bind
    /// keeps the original's tree bound to the original record, and for a
    /// tree-less original writes no snapshot file. Without the cover the
    /// re-bind writes the staged tree. Inert: an offline agent.
    #[tokio::test]
    async fn a_staged_metadata_commit_keeps_the_originals_snapshot_state() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, staged, _) = staged_tree_fixture(&state).await?;
        let next = staged_metadata_commit(&state, &staged)?;
        in_staging(
            &state,
            &key,
            super::super::persist_named_group_info(&state, &key, next),
        )
        .await?;
        let envelope = snapshot_on_disk(&state, &key).await?;
        assert_eq!(envelope.state_hash, original.state_hash);
        assert!(
            envelope.snapshot == original_tree,
            "Keep: the original's tree"
        );

        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, _, staged, _) = treeless_staged_fixture(&state).await?;
        let next = staged_metadata_commit(&state, &staged)?;
        in_staging(
            &state,
            &key,
            super::super::persist_named_group_info(&state, &key, next),
        )
        .await?;
        assert!(
            !snapshot_exists(&state, &key).await?,
            "Absent: no snapshot file"
        );
        Ok(())
    }

    /// #1567 (ZCode on c076826: the hook had no test): the ratchet
    /// persist after an encrypt or decrypt on the staged tree
    /// (`persist_treekem_snapshot_bound`) keeps the original's snapshot
    /// state while the join is staged: the original's tree bound to the
    /// original record (Keep), or no snapshot file (Absent). Without the
    /// cover it writes the staged tree. Inert: an offline agent.
    #[tokio::test]
    async fn a_staged_ratchet_persist_keeps_the_originals_snapshot_state() -> anyhow::Result<()> {
        let staged_tree = |state: Arc<AppState>, key: String| async move {
            state
                .treekem_groups
                .staging_read()
                .await
                .get(&key)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("staged tree"))
        };
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, original_tree, _, _) = staged_tree_fixture(&state).await?;
        let tree = staged_tree(Arc::clone(&state), key.clone()).await?;
        in_staging(&state, &key, async {
            super::super::persist_treekem_snapshot_bound(&state, &key, &*tree.lock().await).await
        })
        .await?;
        let envelope = snapshot_on_disk(&state, &key).await?;
        assert_eq!(envelope.state_hash, original.state_hash);
        assert!(
            envelope.snapshot == original_tree,
            "Keep: the original's tree"
        );

        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, _, _, _) = treeless_staged_fixture(&state).await?;
        let tree = staged_tree(Arc::clone(&state), key.clone()).await?;
        in_staging(&state, &key, async {
            super::super::persist_treekem_snapshot_bound(&state, &key, &*tree.lock().await).await
        })
        .await?;
        assert!(
            !snapshot_exists(&state, &key).await?,
            "Absent: no snapshot file"
        );
        Ok(())
    }

    /// #1567: the tree-less staged persist (`Absent`, roster half only)
    /// keeps the atomic persist's outcomes. `NotReplaced` fails and keeps
    /// the live record; `ReplacedNotDurable` fails as "epoch installed"
    /// with the new record live. Neither writes a snapshot file. Inert:
    /// an offline agent.
    #[tokio::test]
    async fn a_treeless_staged_persist_keeps_the_atomic_outcomes() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, original, staged, _) = treeless_staged_fixture(&state).await?;
        let tree = state
            .treekem_groups
            .staging_read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("staged tree"))?;
        let next = staged_metadata_commit(&state, &staged)?;
        // #1699: the staged record is in the staging slot; the live map
        // keeps the original whatever the staged persist does.
        let live_hash = |state: Arc<AppState>, key: String| async move {
            state
                .named_groups
                .staging_read()
                .await
                .get(&key)
                .map(|info| info.state_hash.clone())
        };
        let original_hash = |state: Arc<AppState>, key: String| async move {
            state
                .named_groups
                .live_read()
                .await
                .get(&key)
                .map(|info| info.state_hash.clone())
        };

        state.named_groups_save_fault.store(1, Ordering::SeqCst);
        let refused = in_staging(&state, &key, async {
            super::super::persist_treekem_and_named_groups_atomic_with_info(
                &state,
                &key,
                next.clone(),
                &*tree.lock().await,
            )
            .await
        })
        .await;
        assert!(refused.is_err());
        assert!(!super::super::self_leave_persist_left_epoch_installed(
            refused
                .as_ref()
                .err()
                .ok_or_else(|| anyhow::anyhow!("err"))?
        ));
        assert_eq!(
            live_hash(Arc::clone(&state), key.clone()).await,
            Some(staged.state_hash.clone())
        );

        state.named_groups_save_fault.store(3, Ordering::SeqCst);
        let installed = in_staging(&state, &key, async {
            super::super::persist_treekem_and_named_groups_atomic_with_info(
                &state,
                &key,
                next.clone(),
                &*tree.lock().await,
            )
            .await
        })
        .await;
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        assert!(super::super::self_leave_persist_left_epoch_installed(
            installed
                .as_ref()
                .err()
                .ok_or_else(|| anyhow::anyhow!("err"))?
        ));
        assert_eq!(
            live_hash(Arc::clone(&state), key.clone()).await,
            Some(next.state_hash.clone())
        );
        assert_eq!(
            original_hash(Arc::clone(&state), key.clone()).await,
            Some(original.state_hash.clone()),
            "the original stays live"
        );
        assert!(!snapshot_exists(&state, &key).await?);
        Ok(())
    }

    /// A group whose admin A seats this node, then two more commits (an
    /// add, then a promotion):
    /// returns A, the group at A's seal (`base`), after one more commit
    /// (`mid`) and after two (`ahead`), and the two links after `base`.
    #[allow(clippy::type_complexity)]
    fn segment_fixture(
        state: &AppState,
    ) -> anyhow::Result<(
        x0x::identity::AgentKeypair,
        GroupInfo,
        GroupInfo,
        GroupInfo,
        Vec<RetainedCommit>,
    )> {
        let admin = x0x::identity::AgentKeypair::generate()?;
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut base = GroupInfo::new(
            "adr0109-segments".to_string(),
            String::new(),
            admin.agent_id(),
            "5109".repeat(16),
        );
        base.add_member(
            local_hex(state),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        base.seal_commit(&admin, 1_000)?;
        let mut mid = base.clone();
        mid.add_member(
            "44".repeat(32),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
        mid.seal_commit(&admin, 2_000)?;
        let mut ahead = mid.clone();
        ahead.set_member_role(&"44".repeat(32), x0x::groups::GroupRole::Admin);
        ahead.seal_commit(&admin, 3_000)?;
        let links = links_after(&base, &ahead);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].commit.state_hash, mid.state_hash);
        Ok((admin, base, mid, ahead, links))
    }

    /// The `awaiting_attestation` view with `reason`.
    fn awaiting(reason: &str) -> Option<SubjectView> {
        Some(SubjectView::Awaiting {
            reason: reason.to_string(),
        })
    }

    /// A fresh subject state for `info`'s group, with no progress since
    /// `start`.
    async fn fresh_subject(state: &AppState, info: &GroupInfo, start: Instant) {
        state.group_recovery.inner.lock().await.subjects.insert(
            info.stable_group_id().to_string(),
            SubjectState::new(start, info.state_revision),
        );
    }

    /// ADR 0109 §2 "Segments" (ZCode on 7726d92: the runtime loop had no
    /// test): the admin-armed ATA covers one of the two links to the kept
    /// terminal. At the segment's last hash the segment is exhausted: the
    /// gate admits nothing, the node keeps a `Gap` ref to the kept
    /// terminal and asks for the next segment at once, with no stall.
    /// Control: one link before the segment end nothing is exhausted, and
    /// the armed gate waits for its stall. This offline node has no capable
    /// peer, so an ask shows as the round reaching target selection
    /// (`no_capable_peer`, which replaces `segment_exhausted`); a held
    /// round keeps the initial `no_reply`. Inert: an offline agent.
    #[tokio::test]
    async fn a_segment_end_before_the_terminal_asks_for_the_next_segment() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (admin, base, mid, ahead, links) = segment_fixture(&state)?;
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let ata = sign_ata(&admin, &local, &base, &links[..1])?;
        let terminal = super::super::NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: ahead.stable_group_id().to_string(),
            revision: links[1].commit.revision,
            actor: admin_hex,
            agent_id: "44".repeat(32),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(links[1].commit.clone()),
        };
        let terminal_json = serde_json::to_vec(&terminal)?;
        let stable = base.stable_group_id().to_string();
        assert!(
            update_sidecar(&state, &stable, move |body| {
                body.active_ata = Some(ata);
                body.queued_terminal = Some(terminal_json);
            })
            .await
        );
        let expected = (links[1].commit.revision, links[1].commit.state_hash.clone());
        let key = base.mls_group_id.clone();
        let start = Instant::now();

        // Control: at `base` the segment's link is still ahead, and the
        // armed gate waits for its stall.
        assert_eq!(exhausted_segment(&state, &base).await, None);
        assert!(armed_admin_ata(&state, &base).await.is_some());
        let base_refs = live_refs(&state, &base).await;
        fresh_subject(&state, &base, start).await;
        assert_eq!(
            next_target(&state, &key, &base, &local, &base_refs, start).await,
            None
        );
        assert_eq!(view_of(&state, &stable).await, awaiting("no_reply"), "held");

        // At the segment's end: exhausted, the gate admits nothing, and
        // the node asks at once.
        assert_eq!(
            exhausted_segment(&state, &mid).await,
            Some(expected.clone())
        );
        assert!(armed_admin_ata(&state, &mid).await.is_none());
        let refs = live_refs(&state, &mid).await;
        assert!(
            refs.iter().any(|r| matches!(
                r,
                RecoveryRef::Gap { reason, terminal_revision, terminal_state_hash, .. }
                    if reason == s3::ADMIN_ATTESTED_GAP_REASON
                        && (*terminal_revision, terminal_state_hash.clone()) == expected
            )),
            "{refs:?}"
        );
        fresh_subject(&state, &mid, start).await;
        assert_eq!(
            next_target(&state, &key, &mid, &local, &refs, start).await,
            None
        );
        assert_eq!(
            view_of(&state, &stable).await,
            awaiting("no_capable_peer"),
            "asked"
        );
        Ok(())
    }

    /// #1726 (W3-H H-S3-x): a backoff holds only at the head it was earned
    /// at. The node's last round asked from `base` and ended with no
    /// answer, so its backoff runs (120 s, the second step); it then moves
    /// to `mid` (here the segment's end, where the next segment is due
    /// now). Its next round starts from `mid` once a responder's
    /// per-requester interval (60 s, §11) has passed since that request,
    /// not after the backoff, and a request still open from `base` is
    /// dropped. Before the fix the node waited out the backoff (240 s at
    /// the third step, up to 1 h). Control: at the head it asked from, the
    /// backoff holds. Inert: an offline agent; an ask shows as
    /// `no_capable_peer`.
    #[tokio::test]
    async fn a_segment_end_after_a_failed_round_asks_without_the_backoff() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (admin, base, mid, ahead, links) = segment_fixture(&state)?;
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let ata = sign_ata(&admin, &local, &base, &links[..1])?;
        let terminal = super::super::NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: ahead.stable_group_id().to_string(),
            revision: links[1].commit.revision,
            actor: admin_hex,
            agent_id: "44".repeat(32),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(links[1].commit.clone()),
        };
        let terminal_json = serde_json::to_vec(&terminal)?;
        let stable = base.stable_group_id().to_string();
        assert!(
            update_sidecar(&state, &stable, move |body| {
                body.active_ata = Some(ata);
                body.queued_terminal = Some(terminal_json);
            })
            .await
        );
        assert!(exhausted_segment(&state, &mid).await.is_some());
        let key = base.mls_group_id.clone();
        let refs = live_refs(&state, &mid).await;
        let start = Instant::now();
        let early = start + Duration::from_secs(1);
        let due = start + s3::RESPONDER_PER_REQUESTER_INTERVAL;
        // Two rounds asked from `info`'s head ended with no answer, the last
        // at `start`; with `open`, a request from that head is still pending.
        let failed_rounds = |info: &GroupInfo, open: bool| {
            let mut subject = SubjectState::new(start, info.state_revision);
            subject.end_round(start);
            subject.end_round(start);
            subject.asked_from = Some((info.state_hash.clone(), start));
            subject.pending = open.then(|| ([7u8; 32], start, info.state_hash.clone()));
            subject
        };
        assert!(failed_rounds(&base, false).next_retry_at > due);
        let set = |subject: SubjectState| {
            let state = &state;
            let stable = stable.clone();
            async move {
                state
                    .group_recovery
                    .inner
                    .lock()
                    .await
                    .subjects
                    .insert(stable, subject);
            }
        };

        // Control: no progress since the failed rounds; the backoff holds
        // past the responder interval.
        set(failed_rounds(&mid, false)).await;
        assert_eq!(
            next_target(&state, &key, &mid, &local, &refs, due).await,
            None
        );
        assert_eq!(
            view_of(&state, &stable).await,
            awaiting("segment_exhausted"),
            "held by the backoff"
        );

        // The rounds failed at `base`, then the node moved to `mid`, with
        // and without a request still open from `base`.
        for open in [false, true] {
            set(failed_rounds(&base, open)).await;
            assert_eq!(
                next_target(&state, &key, &mid, &local, &refs, early).await,
                None
            );
            assert_eq!(
                view_of(&state, &stable).await,
                awaiting("segment_exhausted"),
                "held by the responder interval (open: {open})"
            );
            assert_eq!(
                next_target(&state, &key, &mid, &local, &refs, due).await,
                None
            );
            assert_eq!(
                view_of(&state, &stable).await,
                awaiting("no_capable_peer"),
                "asked after the interval, not the backoff (open: {open})"
            );
        }
        Ok(())
    }

    /// #1726 (Greptile P1 on 02f1e9c7): the responder starts its
    /// per-requester interval (§11) when it admits a request, not when the
    /// requester sent it. The old head's request was sent at 0 s and
    /// admitted at 20 s, so the responder holds the requester until 80 s.
    /// The new head's round restarts at 60 s (the requester's own clock)
    /// and its request is admitted at 65 s: `refused {rate_limited}`. The
    /// requester asks the same target again one interval after that
    /// refusal (past 80 s, so it is admitted), in the same round, and does
    /// not take the old backoff. Before the fix the refusal moved the
    /// round on; with one target the round ended and backed off (240 s at
    /// the third step). A second `rate_limited` from that target in the
    /// round moves the round on as before, so the round still ends.
    #[tokio::test]
    async fn a_new_head_rate_limited_refusal_gets_a_cooldown_retry() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (_key, info, _ata, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        let requester = *state.agent.agent_id().as_bytes();
        let target = *admin.agent_id().as_bytes();
        let interval = s3::RESPONDER_PER_REQUESTER_INTERVAL;

        // The responder side of the race, on its own clock.
        let t0 = Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        let mut budget = ResponderBudget::default();
        assert_eq!(budget.admit(requester, at(20)), Admission::Build);
        budget.finish(0);
        assert_eq!(at(0) + interval, at(60), "the requester's restart");
        assert_eq!(budget.admit(requester, at(65)), Admission::Refuse);
        budget.finish(0);
        // A retry one interval after the refusal (sent at 65 s) is
        // admitted: the interval began at admission (20 s), before it.
        assert_eq!(budget.admit(requester, at(65) + interval), Admission::Build);
        budget.finish(0);

        // The requester side: two rounds failed at the old head, then the
        // new head's round asked `target`, which refuses `rate_limited`.
        let rate_limited = || GroupAttestResponseV1 {
            group: stable.clone(),
            subject: requester,
            for_head_state_hash: info.state_hash.clone(),
            answer: AttestAnswer::Refused(AttestRefusalReason::RateLimited),
        };
        let ask = |at: Instant| {
            let state = &state;
            let stable = stable.clone();
            let head = info.state_hash.clone();
            let revision = info.state_revision;
            async move {
                let mut inner = state.group_recovery.inner.lock().await;
                let subject = inner
                    .subjects
                    .entry(stable)
                    .or_insert_with(|| SubjectState::new(at, revision));
                subject.pending = Some((target, at, head.clone()));
                subject.asked_from = Some((head, at));
            }
        };
        let snapshot = || {
            let state = &state;
            let stable = stable.clone();
            async move {
                state
                    .group_recovery
                    .inner
                    .lock()
                    .await
                    .subjects
                    .get(&stable)
                    .map(|s| (s.attempts, s.next_target, s.next_retry_at, s.view.clone()))
            }
        };
        {
            let mut subject = SubjectState::new(t0, info.state_revision);
            subject.end_round(t0);
            subject.end_round(t0);
            state
                .group_recovery
                .inner
                .lock()
                .await
                .subjects
                .insert(stable.clone(), subject);
        }
        ask(Instant::now()).await;
        let before = Instant::now();
        handle_response(&state, admin.agent_id(), rate_limited()).await;
        let after = Instant::now();
        let (attempts, next, retry_at, view) =
            snapshot().await.ok_or_else(|| anyhow::anyhow!("subject"))?;
        assert_eq!(attempts, 2, "the round did not end");
        assert_eq!(next, 0, "the same target is asked again");
        assert!(
            retry_at >= before + interval && retry_at <= after + interval,
            "the retry waits one interval after the refusal"
        );
        assert!(after + interval < before + s3::request_backoff(2));
        assert_eq!(Some(view), awaiting("rate_limited"));

        // The cooldown retry is refused too: the round moves on.
        ask(Instant::now()).await;
        handle_response(&state, admin.agent_id(), rate_limited()).await;
        let (attempts, next, _, _) = snapshot().await.ok_or_else(|| anyhow::anyhow!("subject"))?;
        assert_eq!(
            (attempts, next),
            (2, 1),
            "one cooldown per target per round"
        );
        // A new round gives each target its cooldown again.
        let mut inner = state.group_recovery.inner.lock().await;
        let subject = inner
            .subjects
            .get_mut(&stable)
            .ok_or_else(|| anyhow::anyhow!("subject"))?;
        assert_eq!(subject.cooled, Some(target));
        subject.end_round(Instant::now());
        assert_eq!(subject.cooled, None);
        Ok(())
    }

    /// ADR 0109 §2 "Requests" (ZCode on 7726d92): an admin-armed ATA with
    /// no progress asks for its renewal after `ATA_ARMED_LIFETIME`, not
    /// after `GATE_STALL`. As in the segment test, an offline node's ask
    /// shows as `no_capable_peer` and a held round keeps `no_reply`.
    /// Inert: an offline agent.
    #[tokio::test]
    async fn an_armed_ata_without_progress_asks_for_renewal() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (admin, base, _, _, links) = segment_fixture(&state)?;
        let ata = sign_ata(&admin, &local, &base, &links)?;
        let stable = base.stable_group_id().to_string();
        assert!(update_sidecar(&state, &stable, move |body| body.active_ata = Some(ata)).await);
        let refs = live_refs(&state, &base).await;
        assert_eq!(refs.len(), 1, "only the admin-armed gap: {refs:?}");
        let key = base.mls_group_id.clone();
        let start = Instant::now();
        fresh_subject(&state, &base, start).await;
        assert!(s3::GATE_STALL < s3::ATA_ARMED_LIFETIME);
        for held in [
            start + s3::GATE_STALL,
            start + s3::ATA_ARMED_LIFETIME - Duration::from_secs(1),
        ] {
            assert_eq!(
                next_target(&state, &key, &base, &local, &refs, held).await,
                None
            );
            assert_eq!(view_of(&state, &stable).await, awaiting("no_reply"), "held");
        }
        let due = start + s3::ATA_ARMED_LIFETIME;
        assert_eq!(
            next_target(&state, &key, &base, &local, &refs, due).await,
            None
        );
        assert_eq!(
            view_of(&state, &stable).await,
            awaiting("no_capable_peer"),
            "asked"
        );
        Ok(())
    }

    /// #1533 review (Codex P2 and P1): every S3 write needs the
    /// recipient's current verified `group_terminal_attest_v1`. A legacy
    /// recipient (no advert) gets nothing, not even a refusal, under every
    /// guard. A marker on the issuer's record counts as contained for both
    /// the admission and the write-seam check. Daemon-level; CI only.
    #[tokio::test]
    async fn s3_admission_refuses_legacy_recipients_and_contained_issuers() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _) = reseat_fixture(&state).await?;
        let legacy = x0x::identity::AgentKeypair::generate()?.agent_id();
        for guard in [Guard::Refusal, Guard::Member, Guard::Reseat([0; 32])] {
            let admit = admission(&state, &key, legacy, guard);
            assert!(
                admit().await.is_none(),
                "{guard:?}: a legacy recipient gets nothing"
            );
        }
        let mut contained_info = info.clone();
        contained_info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: info.state_revision,
            state_hash: "sibling".to_string(),
            committed_by: local_hex(&state),
            observed_at_ms: 1,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        });
        assert!(contained(&state, &contained_info).await);
        assert!(record_contained(&contained_info));
        Ok(())
    }

    /// Codex P1 (#1533 round 1): a conflicting attestation must stop
    /// application at the common prefix (ADR 0109 §2 "Conflict"). Before
    /// the fix the conflict changed only the view, and the catch-up gate
    /// kept the active ATA's full sequence. The bound is the shared
    /// [`conflict_admits_commit`] gate (r5); the routes are covered by
    /// `a_conflict_bounds_every_delivery_route_at_the_common_prefix`.
    #[tokio::test]
    async fn conflicting_attestation_narrows_the_gate_to_the_common_prefix() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let admin = x0x::identity::AgentKeypair::generate()?;
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut info = GroupInfo::new(
            "adr0109-conflict".to_string(),
            String::new(),
            admin.agent_id(),
            "3109".repeat(16),
        );
        info.add_member(
            local.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.seal_commit(&admin, 1_000)?;
        let key = info.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        let stable = info.stable_group_id().to_string();
        let ata = |sequence: &[&str]| {
            AdminTerminalAttestation::sign(
                AtaFields {
                    group: stable.clone(),
                    subject: local.clone(),
                    attested_by: admin_hex.clone(),
                    signer_public_key: hex::encode(admin.public_key().as_bytes()),
                    from_revision: info.state_revision,
                    from_state_hash: info.state_hash.clone(),
                    sequence: sequence.iter().map(|hash| (*hash).to_string()).collect(),
                    segment_terminal_revision: info.state_revision + sequence.len() as u64,
                    segment_terminal_epoch: None,
                    issued_at_ms: now_ms(),
                },
                &admin,
            )
        };
        let active = ata(&["a1", "a2", "a3"])?;
        arm_from_response(&state, &key, &info, active.clone()).await;
        assert_eq!(
            armed_admin_sequence(&state, &info).await,
            Some(active.fields.sequence.clone()),
            "armed: the gate admits the active sequence"
        );
        let conflicting = ata(&["a1", "x2"])?;
        arm_from_response(&state, &key, &info, conflicting).await;
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(
            body.attestation_conflict.is_some(),
            "the conflict is durable"
        );
        assert_eq!(body.active_ata.as_ref(), Some(&active));
        let bound = |body: &GroupRecoveryV1, link: &str| {
            matches!(
                (body.active_ata.as_ref(), body.attestation_conflict.as_ref()),
                (Some(active), Some(conflict))
                    if s3::conflict_admits_link(active, conflict, &info.state_hash, link)
            )
        };
        assert!(bound(&body, "a1"), "the common prefix applies");
        assert!(
            !bound(&body, "a2") && !bound(&body, "x2"),
            "nothing past the common prefix applies"
        );
        assert!(matches!(
            view_of(&state, &stable).await,
            Some(SubjectView::Reseat {
                cause: "attestation_conflict",
                ..
            })
        ));
        // A later agreeing ATA arms nothing: catch-up stays stopped.
        let agreeing = ata(&["a1", "a2", "a3"])?;
        arm_from_response(&state, &key, &info, agreeing).await;
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert_eq!(body.active_ata.as_ref(), Some(&active));
        assert!(bound(&body, "a1") && !bound(&body, "a2"));
        Ok(())
    }

    /// #1533 rc15 Codex P1 (ADR 0109 §2 "Conflict"): a later reply whose
    /// common prefix with the active ATA is shorter narrows the gate, on
    /// the receiver path. Active `[a1,a2]`, then `[a1,x2]`, then
    /// `[y1,y2]`: the common prefix is empty, so `a1` does not apply.
    /// Before the fix the receiver stopped at the first recorded conflict
    /// and the gate still admitted `a1`.
    #[tokio::test]
    async fn a_later_reply_with_a_shorter_prefix_narrows_the_gate() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, active, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        let sequence = |links: &[&str]| -> anyhow::Result<AdminTerminalAttestation> {
            let mut fields = active.fields.clone();
            fields.sequence = links.iter().map(|link| (*link).to_string()).collect();
            Ok(AdminTerminalAttestation::sign(fields, &admin)?)
        };
        let admits = |body: &GroupRecoveryV1, link: &str| {
            matches!(
                (body.active_ata.as_ref(), body.attestation_conflict.as_ref()),
                (Some(active), Some(conflict))
                    if s3::conflict_admits_link(active, conflict, &info.state_hash, link)
            )
        };
        arm_from_response(&state, &key, &info, active.clone()).await;
        arm_from_response(&state, &key, &info, sequence(&["a1", "x2"])?).await;
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert_eq!(body.active_ata.as_ref(), Some(&active));
        assert!(admits(&body, "a1"), "the prefix [a1] applies");

        arm_from_response(&state, &key, &info, sequence(&["y1", "y2"])?).await;
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert_eq!(body.active_ata.as_ref(), Some(&active));
        assert!(
            !admits(&body, "a1"),
            "the empty common prefix admits nothing"
        );
        let on_disk = sidecar_on_disk(&state, &stable).await?;
        assert!(!admits(&on_disk, "a1"), "the narrower bound is durable");

        // A weaker reply does not move the bound forward again.
        arm_from_response(&state, &key, &info, sequence(&["a1", "z2"])?).await;
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(!admits(&body, "a1"));
        Ok(())
    }

    /// #1533 rc15 Codex P1 (ADR 0109 §2 "Conflict"): a conflict is
    /// recorded under the group's membership lock. A local commit holds
    /// that lock from its conflict check until it is saved and published,
    /// so the record waits for it. Before the fix the record was written
    /// while the commit was in flight, and the commit then installed past
    /// the new common prefix.
    #[tokio::test]
    async fn a_conflict_record_waits_for_a_local_commit_in_flight() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, active, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        arm_from_response(&state, &key, &info, active.clone()).await;
        let mut fields = active.fields.clone();
        fields.sequence = vec!["y1".to_string(), "y2".to_string()];
        let conflict = AdminTerminalAttestation::sign(fields, &admin)?;

        let lock = super::super::group_membership_lock(&state, &key).await;
        let commit_in_flight = lock.lock().await;
        let record = {
            let (state, key, info) = (Arc::clone(&state), key.clone(), info.clone());
            tokio::spawn(async move { record_conflict(&state, &key, &info, conflict).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!record.is_finished(), "the record waits for the lock");
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(
            body.attestation_conflict.is_none(),
            "no conflict is recorded while a local commit holds the lock"
        );
        drop(commit_in_flight);
        record.await?;
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(body.attestation_conflict.is_some(), "then it is recorded");
        Ok(())
    }

    /// #1533 r8 Codex P1 2 (ADR 0109 §2 "Conflict"): two conflicting
    /// replies that arrive together both pass the early check (no active
    /// ATA yet). The compare and the install are one sidecar write, so the
    /// second reply records the conflict and does not replace the first.
    /// Before the fix the second `arm_in_place` installed its ATA over the
    /// first and no conflict was recorded.
    #[tokio::test]
    async fn simultaneous_conflicting_replies_record_the_conflict() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, first, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        let mut fields = first.fields.clone();
        fields.sequence = vec!["a1".to_string(), "x2".to_string()];
        let second = AdminTerminalAttestation::sign(fields, &admin)?;
        anyhow::ensure!(first.conflicts_with(&second));

        tokio::join!(
            arm_from_response(&state, &key, &info, first.clone()),
            arm_from_response(&state, &key, &info, second.clone()),
        );
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        let active = body
            .active_ata
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("one reply is armed"))?;
        let conflict = body
            .attestation_conflict
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("the conflict is recorded"))?;
        assert!(
            (active == &first && conflict == &second) || (active == &second && conflict == &first),
            "the first armed reply stays active and the other is the conflict"
        );
        let on_disk = sidecar_on_disk(&state, &stable).await?;
        assert!(
            on_disk.attestation_conflict.is_some(),
            "the conflict is durable"
        );
        Ok(())
    }

    /// #1533 r8 Codex P1 1 (ADR 0109 §2 "Conflict"): every commit this
    /// node seals passes the conflict gate, not only a rebind. This node
    /// is the group's admin and holds a recorded conflict on its head (no
    /// fork marker). The ordinary rename route and a direct seal through
    /// the shared wrapper (which `crypto_exclusion::commit_locked` and
    /// `owner_recovery::finish_commit` also use) must refuse and leave the
    /// record unchanged. Before the fix both sealed past the common
    /// prefix and the route persisted the new head.
    #[tokio::test]
    async fn a_recorded_conflict_refuses_every_local_author() -> anyhow::Result<()> {
        use axum::extract::{Json, Path, State};
        use axum::response::IntoResponse;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let me = state.agent.identity().agent_keypair();
        let mut info = GroupInfo::new(
            "adr0109-local-author".to_string(),
            String::new(),
            me.agent_id(),
            "5109".repeat(16),
        );
        info.seal_commit(me, 1_000)?;
        let key = info.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        anyhow::ensure!(
            record_conflict_at_head_for_test(&state, &info).await?,
            "the conflict is durable"
        );

        let req: super::super::UpdateGroupRequest =
            serde_json::from_value(serde_json::json!({ "description": "past the prefix" }))?;
        let response = super::super::update_named_group(
            State(Arc::clone(&state)),
            axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
            Path(key.clone()),
            Json(req),
        )
        .await
        .into_response();
        assert_ne!(response.status(), axum::http::StatusCode::OK);
        let live = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("group"))?;
        assert_eq!(live.state_hash, info.state_hash, "the head did not move");
        assert_eq!(live.description, info.description);
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert_eq!(legacy.state_hash, info.state_hash, "nothing persisted");

        // The shared wrapper itself refuses and leaves the working copy.
        let mut next = live.clone();
        next.description = "past the prefix".to_string();
        let before = next.clone();
        assert!(
            super::super::seal_commit_owner_certified(&state, &mut next, me, 2_000)
                .await
                .is_err()
        );
        assert_eq!(next.state_hash, before.state_hash);
        assert_eq!(next.state_revision, before.state_revision);
        assert_eq!(next.commit_log.len(), before.commit_log.len());
        Ok(())
    }

    /// #1533 r9 Codex P1 2 (ADR 0109 §2 "Conflict"): two replies can both
    /// record a conflict. With active `[a1, a2]`, a conflict `[x1, x2]`
    /// bounds the gate at the head (empty prefix). A later conflict
    /// `[a1, z2]` replaced it and moved the bound to `[a1]`. The record now
    /// keeps the strongest bound, in either order, durably and in the
    /// memory-only fallback.
    #[tokio::test]
    async fn a_later_conflict_never_weakens_the_bound() -> anyhow::Result<()> {
        for strong_first in [true, false] {
            let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
            let (key, info, first, admin) = armed_fixture_with_signer(&state).await?;
            let stable = info.stable_group_id().to_string();
            let with_sequence = |sequence: &[&str]| {
                let mut fields = first.fields.clone();
                fields.sequence = sequence.iter().map(|hash| (*hash).to_string()).collect();
                AdminTerminalAttestation::sign(fields, &admin)
            };
            let active = with_sequence(&["a1", "a2"])?;
            assert!(
                update_sidecar(&state, &stable, |body| body.active_ata =
                    Some(active.clone()))
                .await
            );
            let strong = with_sequence(&["x1", "x2"])?;
            let weak = with_sequence(&["a1", "z2"])?;
            let order = if strong_first {
                [strong.clone(), weak.clone()]
            } else {
                [weak.clone(), strong.clone()]
            };
            for conflict in order.clone() {
                record_conflict(&state, &key, &info, conflict).await;
            }
            for body in [
                sidecar_snapshot(&state, &stable).await.unwrap_or_default(),
                sidecar_on_disk(&state, &stable).await?,
            ] {
                assert_eq!(
                    body.attestation_conflict.as_ref(),
                    Some(&strong),
                    "strong_first={strong_first}: the strongest bound is kept"
                );
                assert_eq!(body.active_ata.as_ref(), Some(&active));
                assert!(
                    !s3::conflict_admits_link(&active, &strong, &info.state_hash, "a1"),
                    "nothing past the empty common prefix applies"
                );
            }
            // The memory-only fallback uses the same rule.
            let mut body = GroupRecoveryV1 {
                active_ata: Some(active.clone()),
                ..GroupRecoveryV1::default()
            };
            for conflict in order {
                keep_strongest_conflict(&mut body, conflict);
            }
            assert_eq!(body.attestation_conflict.as_ref(), Some(&strong));
        }
        Ok(())
    }

    /// #1533 r9 Codex P2 (ADR 0109 §4 "S3 publishes to the live map only
    /// when both writes are Durable"): the join carry advances the record.
    /// On a `ReplacedNotDurable` legacy write the shared persist helper
    /// kept the advanced record in the live map. Now the live map keeps
    /// the record from before the carry, the group stays contained
    /// (placeheld, ATA kept) and the worker's retry writes the placeholder
    /// durably.
    #[tokio::test]
    async fn join_carry_not_durable_publishes_nothing() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let owner = x0x::identity::AgentKeypair::generate()?;
        let owner_hex = hex::encode(owner.agent_id().as_bytes());
        let mut base = GroupInfo::new(
            "adr0109-carry-not-durable".to_string(),
            String::new(),
            owner.agent_id(),
            "7109".repeat(16),
        );
        base.seal_commit(&owner, 1_000)?;
        let key = base.mls_group_id.clone();
        let stable = base.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), base.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let mut ahead = base.clone();
        ahead.name = "renamed".to_string();
        ahead.seal_commit(&owner, 2_000)?;
        let links = links_after(&base, &ahead);
        let mut joined = ahead.clone();
        joined.add_member(
            local.clone(),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
        joined.seal_commit(&owner, 3_000)?;
        let terminal = joined
            .commit_log
            .last()
            .map(|entry| entry.commit.clone())
            .ok_or_else(|| anyhow::anyhow!("terminal"))?;
        let event = super::super::NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: stable.clone(),
            revision: terminal.revision,
            actor: owner_hex.clone(),
            name: None,
            description: None,
            commit: Some(terminal.clone()),
        };
        let ata = sign_ata(&owner, &local, &base, &links)?;

        state.named_groups_save_fault.store(3, Ordering::SeqCst);
        let applied = apply_join_carry(&state, &key, &links, &terminal, &event, &ata).await;
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        assert!(!applied, "not published");
        assert_eq!(
            head_of(&state, &key).await.as_deref(),
            Some(base.state_hash.as_str()),
            "the live map keeps the record from before the carry"
        );
        assert!(is_placeheld(&state, &stable), "stays contained");
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(body.active_ata.is_some(), "the ATA is kept");
        // The worker's retry writes the placeholder durably; the live
        // record still does not move.
        ensure_placeholders(&state).await;
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(s3::is_s3_placeholder(&legacy));
        assert_eq!(
            head_of(&state, &key).await.as_deref(),
            Some(base.state_hash.as_str())
        );
        Ok(())
    }

    /// #1574 slice 3 (Engineer ruling, 30 Oct 19:32 GMT): when the
    /// durability preflight refuses AFTER its confirming re-save renamed
    /// the placeholder onto disk, the S3 arming stays contained — disk
    /// and the sidecar agree. A `NotReplaced` mapping of that refusal
    /// would clear the sidecar's arming while the placeholder survives
    /// on disk: a crash before the next good save then leaves the
    /// orphan that load reconciliation never repairs (#1708's shape).
    #[tokio::test]
    async fn a_preflight_refusal_after_rename_keeps_the_s3_arming_contained() -> anyhow::Result<()>
    {
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let owner = x0x::identity::AgentKeypair::generate()?;
        let owner_hex = hex::encode(owner.agent_id().as_bytes());
        let mut base = GroupInfo::new(
            "adr0109-carry-preflight-refused".to_string(),
            String::new(),
            owner.agent_id(),
            "7209".repeat(16),
        );
        base.seal_commit(&owner, 1_000)?;
        let key = base.mls_group_id.clone();
        let stable = base.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), base.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let mut ahead = base.clone();
        ahead.name = "renamed".to_string();
        ahead.seal_commit(&owner, 2_000)?;
        let links = links_after(&base, &ahead);
        let mut joined = ahead.clone();
        joined.add_member(
            local.clone(),
            x0x::groups::GroupRole::Member,
            Some(owner_hex.clone()),
            None,
        );
        joined.seal_commit(&owner, 3_000)?;
        let terminal = joined
            .commit_log
            .last()
            .map(|entry| entry.commit.clone())
            .ok_or_else(|| anyhow::anyhow!("terminal"))?;
        let event = super::super::NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: stable.clone(),
            revision: terminal.revision,
            actor: owner_hex.clone(),
            name: None,
            description: None,
            commit: Some(terminal.clone()),
        };
        let ata = sign_ata(&owner, &local, &base, &links)?;
        // The preflight refuses after its re-save renamed the current
        // map — the S3 placeholder included — onto disk.
        state
            .named_groups_requires_durability_confirmation
            .store(true, Ordering::SeqCst);
        state.named_groups_save_fault.store(4, Ordering::SeqCst);
        let applied = apply_join_carry(&state, &key, &links, &terminal, &event, &ata).await;
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        assert!(!applied, "not published");
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(
            s3::is_s3_placeholder(&legacy),
            "the refusal's re-save put the placeholder on disk"
        );
        assert!(is_placeheld(&state, &stable), "the arming stays contained");
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(
            body.active_ata.is_some(),
            "the sidecar keeps the ATA, so disk and sidecar agree"
        );
        assert_eq!(
            head_of(&state, &key).await.as_deref(),
            Some(base.state_hash.as_str()),
            "the live map keeps the record from before the carry"
        );
        Ok(())
    }

    /// The links of `ahead` after `base`'s head, in order.
    fn links_after(base: &GroupInfo, ahead: &GroupInfo) -> Vec<RetainedCommit> {
        ahead
            .commit_log
            .iter()
            .filter(|entry| entry.commit.revision > base.state_revision)
            .cloned()
            .collect()
    }

    fn sign_ata(
        signer: &x0x::identity::AgentKeypair,
        subject: &str,
        from: &GroupInfo,
        links: &[RetainedCommit],
    ) -> anyhow::Result<AdminTerminalAttestation> {
        Ok(AdminTerminalAttestation::sign(
            AtaFields {
                group: from.stable_group_id().to_string(),
                subject: subject.to_string(),
                attested_by: hex::encode(signer.agent_id().as_bytes()),
                signer_public_key: hex::encode(signer.public_key().as_bytes()),
                from_revision: from.state_revision,
                from_state_hash: from.state_hash.clone(),
                sequence: links
                    .iter()
                    .map(|link| link.commit.state_hash.clone())
                    .collect(),
                segment_terminal_revision: links
                    .last()
                    .map_or(from.state_revision, |link| link.commit.revision),
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            signer,
        )?)
    }

    /// Codex P1 G3 (#1533 round 3), ADR 0109 §2 "If the signer stops
    /// being an active admin after an applied link, the gate stops
    /// there", join-carry path: a served link that demotes or removes the
    /// ATA's signer applies, and the attested links after it do not.
    #[tokio::test]
    async fn join_carry_stops_after_the_link_that_unseats_the_signer() -> anyhow::Result<()> {
        for removal in [false, true] {
            let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
            let local = local_hex(&state);
            let owner = x0x::identity::AgentKeypair::generate()?;
            let owner_hex = hex::encode(owner.agent_id().as_bytes());
            let signer = x0x::identity::AgentKeypair::generate()?;
            let signer_hex = hex::encode(signer.agent_id().as_bytes());
            let mut base = GroupInfo::new(
                "adr0109-unseated-signer".to_string(),
                String::new(),
                owner.agent_id(),
                "5109".repeat(16),
            );
            base.add_member(
                signer_hex.clone(),
                x0x::groups::GroupRole::Admin,
                Some(owner_hex.clone()),
                None,
            );
            base.seal_commit(&owner, 1_000)?;
            assert!(!base.has_active_member(&local), "a pre-Welcome joiner");
            let key = base.mls_group_id.clone();
            state
                .named_groups
                .write()
                .await
                .insert(key.clone(), base.clone());
            assert!(matches!(
                super::super::save_named_groups_checked(&state).await?,
                super::super::AtomicWriteOutcome::Durable
            ));
            let mut ahead = base.clone();
            if removal {
                ahead.remove_member(&signer_hex, Some(owner_hex.clone()));
            } else {
                ahead.set_member_role(&signer_hex, x0x::groups::GroupRole::Member);
            }
            ahead.seal_commit(&owner, 2_000)?;
            ahead.name = "renamed".to_string();
            ahead.seal_commit(&owner, 3_000)?;
            let links = links_after(&base, &ahead);
            assert_eq!(links.len(), 2);
            let mut joined = ahead.clone();
            joined.add_member(
                local.clone(),
                x0x::groups::GroupRole::Member,
                Some(owner_hex.clone()),
                None,
            );
            joined.seal_commit(&owner, 4_000)?;
            let terminal = joined
                .commit_log
                .last()
                .map(|entry| entry.commit.clone())
                .ok_or_else(|| anyhow::anyhow!("terminal"))?;
            let event = super::super::NamedGroupMetadataEvent::GroupMetadataUpdated {
                group_id: base.stable_group_id().to_string(),
                revision: terminal.revision,
                actor: owner_hex.clone(),
                name: None,
                description: None,
                commit: Some(terminal.clone()),
            };
            let ata = sign_ata(&signer, &local, &base, &links)?;
            assert!(ata.signer_verified_on(&base));
            let _ = apply_join_carry(&state, &key, &links, &terminal, &event, &ata).await;
            let head = state
                .named_groups
                .read()
                .await
                .get(&key)
                .map(|info| info.state_hash.clone());
            assert_eq!(
                head.as_deref(),
                Some(links[0].commit.state_hash.as_str()),
                "removal={removal}: the link that unseats the signer applies; the link after it does not (base {}, second link {})",
                base.state_hash,
                links[1].commit.state_hash
            );
        }
        Ok(())
    }

    /// Codex P1 G3 (#1533 round 3), the same rule on the catch-up page
    /// path: the page gate is checked before the page, and each commit is
    /// checked again against the record the earlier commits left. A page
    /// whose first commit demotes the signer adopts that commit only.
    #[tokio::test]
    async fn catchup_page_stops_after_the_commit_that_demotes_the_signer() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let owner = x0x::identity::AgentKeypair::generate()?;
        let owner_hex = hex::encode(owner.agent_id().as_bytes());
        let signer = x0x::identity::AgentKeypair::generate()?;
        let signer_hex = hex::encode(signer.agent_id().as_bytes());
        let other_hex = "33".repeat(32);
        let mut base = GroupInfo::new(
            "adr0109-demoted-page".to_string(),
            String::new(),
            owner.agent_id(),
            "6109".repeat(16),
        );
        for (member, role) in [
            (&signer_hex, x0x::groups::GroupRole::Admin),
            (&local, x0x::groups::GroupRole::Member),
            (&other_hex, x0x::groups::GroupRole::Member),
        ] {
            base.add_member(member.clone(), role, Some(owner_hex.clone()), None);
        }
        base.seal_commit(&owner, 1_000)?;
        let key = base.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), base.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let mut ahead = base.clone();
        ahead.set_member_role(&signer_hex, x0x::groups::GroupRole::Member);
        ahead.seal_commit(&owner, 2_000)?;
        ahead.set_member_role(&other_hex, x0x::groups::GroupRole::Admin);
        ahead.seal_commit(&owner, 3_000)?;
        let links = links_after(&base, &ahead);
        assert_eq!(links.len(), 2);
        let ata = sign_ata(&signer, &local, &base, &links)?;
        let stable = base.stable_group_id().to_string();
        let kept = ata.clone();
        assert!(update_sidecar(&state, &stable, move |body| body.active_ata = Some(kept)).await);
        assert_eq!(
            armed_admin_sequence(&state, &base).await,
            Some(ata.fields.sequence.clone()),
            "the page gate is armed with the whole sequence"
        );
        let events = [(&signer_hex, &links[0]), (&other_hex, &links[1])]
            .into_iter()
            .map(
                |(agent, link)| super::super::NamedGroupMetadataEvent::MemberRoleUpdated {
                    group_id: stable.clone(),
                    revision: link.commit.revision,
                    actor: owner_hex.clone(),
                    agent_id: agent.clone(),
                    role: if *agent == signer_hex {
                        x0x::groups::GroupRole::Member
                    } else {
                        x0x::groups::GroupRole::Admin
                    },
                    commit: Some(link.commit.clone()),
                },
            )
            .collect();
        super::super::handle_treekem_catchup_response(
            &state,
            &owner.agent_id(),
            &clean_sender_machine(),
            true,
            super::super::TreeKemCatchupResponse {
                message_type: "treekem_catchup_response".to_string(),
                group_id: key.clone(),
                events,
                truncated: false,
                responder_state_hash: None,
            },
        )
        .await;
        let head = state
            .named_groups
            .read()
            .await
            .get(&key)
            .map(|info| info.state_hash.clone());
        assert_eq!(
            head.as_deref(),
            Some(links[0].commit.state_hash.as_str()),
            "the demoting commit applies; the commit after it does not (base {}, second commit {})",
            base.state_hash,
            links[1].commit.state_hash
        );
        Ok(())
    }

    /// The §2 "Conflict" fixture: a group with the owner, an admin
    /// `signer`, this node and two other members, durable on disk. `links`
    /// are two owner role-change commits after `base`, and `events` carry
    /// them. The signer's ATA for both links arms through the request path
    /// (`arm_from_response`, durable), then the owner's ATA that diverges
    /// after the first link is recorded as the conflict through the same
    /// path. The common prefix is the first link.
    async fn conflict_fixture(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(
        String,
        GroupInfo,
        Vec<RetainedCommit>,
        Vec<super::super::NamedGroupMetadataEvent>,
        x0x::identity::AgentKeypair,
    )> {
        let local = local_hex(state);
        let owner = x0x::identity::AgentKeypair::generate()?;
        let owner_hex = hex::encode(owner.agent_id().as_bytes());
        let signer = x0x::identity::AgentKeypair::generate()?;
        let signer_hex = hex::encode(signer.agent_id().as_bytes());
        let first_hex = "41".repeat(32);
        let second_hex = "42".repeat(32);
        let mut base = GroupInfo::new(
            "adr0109-conflict-routes".to_string(),
            String::new(),
            owner.agent_id(),
            "7109".repeat(16),
        );
        for (member, role) in [
            (&signer_hex, x0x::groups::GroupRole::Admin),
            (&local, x0x::groups::GroupRole::Member),
            (&first_hex, x0x::groups::GroupRole::Member),
            (&second_hex, x0x::groups::GroupRole::Member),
        ] {
            base.add_member(member.clone(), role, Some(owner_hex.clone()), None);
        }
        base.seal_commit(&owner, 1_000)?;
        let key = base.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), base.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let mut ahead = base.clone();
        ahead.set_member_role(&first_hex, x0x::groups::GroupRole::Admin);
        ahead.seal_commit(&owner, 2_000)?;
        ahead.set_member_role(&second_hex, x0x::groups::GroupRole::Admin);
        ahead.seal_commit(&owner, 3_000)?;
        let links = links_after(&base, &ahead);
        assert_eq!(links.len(), 2);
        let stable = base.stable_group_id().to_string();
        let events = [(&first_hex, &links[0]), (&second_hex, &links[1])]
            .into_iter()
            .map(
                |(agent, link)| super::super::NamedGroupMetadataEvent::MemberRoleUpdated {
                    group_id: stable.clone(),
                    revision: link.commit.revision,
                    actor: owner_hex.clone(),
                    agent_id: agent.clone(),
                    role: x0x::groups::GroupRole::Admin,
                    commit: Some(link.commit.clone()),
                },
            )
            .collect();
        let active = sign_ata(&signer, &local, &base, &links)?;
        arm_from_response(state, &key, &base, active.clone()).await;
        assert_eq!(
            sidecar_on_disk(state, &stable).await?.active_ata,
            Some(active.clone()),
            "the signer's ATA is armed durably"
        );
        let conflicting = AdminTerminalAttestation::sign(
            AtaFields {
                group: stable.clone(),
                subject: local.clone(),
                attested_by: owner_hex.clone(),
                signer_public_key: hex::encode(owner.public_key().as_bytes()),
                from_revision: base.state_revision,
                from_state_hash: base.state_hash.clone(),
                sequence: vec![links[0].commit.state_hash.clone(), "x2".to_string()],
                segment_terminal_revision: base.state_revision + 2,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &owner,
        )?;
        arm_from_response(state, &key, &base, conflicting).await;
        let body = sidecar_on_disk(state, &stable).await?;
        assert!(
            body.attestation_conflict.is_some(),
            "the conflict is durable"
        );
        assert_eq!(body.active_ata, Some(active));
        Ok((key, base, links, events, owner))
    }

    async fn head_of(state: &AppState, key: &str) -> Option<String> {
        state
            .named_groups
            .read()
            .await
            .get(key)
            .map(|info| info.state_hash.clone())
    }

    /// A machine id no revocation set lists: recovery pages must stay on the
    /// clean side of the #1616 machine gate.
    fn clean_sender_machine() -> x0x::identity::MachineId {
        x0x::identity::MachineId([0x16; 32])
    }

    /// One catch-up page from `sender` carrying `events`.
    async fn deliver_page(
        state: &Arc<AppState>,
        key: &str,
        sender: AgentId,
        events: Vec<super::super::NamedGroupMetadataEvent>,
    ) {
        super::super::handle_treekem_catchup_response(
            state,
            &sender,
            &clean_sender_machine(),
            true,
            super::super::TreeKemCatchupResponse {
                message_type: "treekem_catchup_response".to_string(),
                group_id: key.to_string(),
                events,
                truncated: false,
                responder_state_hash: None,
            },
        )
        .await;
    }

    /// Codex P1 (#1533 r5, conflict limit), ADR 0109 §2 "Conflict":
    /// "Nothing past the common prefix applies" holds for every delivery
    /// route. The ordinary DM / gossip apply (`apply_named_group_metadata_event`)
    /// takes the link inside the common prefix and refuses the link past
    /// it; a catch-up page with the link past it is refused too. Before the
    /// fix only catch-up pages were bounded, and a valid role-change commit
    /// by DM or gossip applied past the prefix. Inert.
    #[tokio::test]
    async fn a_conflict_bounds_every_delivery_route_at_the_common_prefix() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, base, links, events, owner) = conflict_fixture(&state).await?;
        let mut events = events.into_iter();
        let (Some(inside), Some(past)) = (events.next(), events.next()) else {
            anyhow::bail!("two events");
        };
        assert_eq!(head_of(&state, &key).await, Some(base.state_hash.clone()));
        let applied = super::super::apply_named_group_metadata_event(
            &state,
            inside,
            owner.agent_id(),
            true,
            None,
        )
        .await;
        assert!(
            applied.accepted,
            "the link inside the common prefix applies by DM"
        );
        assert_eq!(
            head_of(&state, &key).await,
            Some(links[0].commit.state_hash.clone())
        );
        let applied = super::super::apply_named_group_metadata_event(
            &state,
            past.clone(),
            owner.agent_id(),
            true,
            None,
        )
        .await;
        assert!(
            !applied.accepted,
            "the link past the common prefix is refused by DM / gossip"
        );
        assert_eq!(
            head_of(&state, &key).await,
            Some(links[0].commit.state_hash.clone()),
            "nothing past the common prefix applies (DM / gossip)"
        );
        deliver_page(&state, &key, owner.agent_id(), vec![past]).await;
        assert_eq!(
            head_of(&state, &key).await,
            Some(links[0].commit.state_hash.clone()),
            "nothing past the common prefix applies (catch-up page)"
        );
        Ok(())
    }

    /// Codex P1 (#1533 r5, restart), ADR 0109 §2 "Conflict" and §4: the
    /// conflict keeps its bound across a restart. Arm durably, record the
    /// conflict, restart before any link applied (drop the state, load the
    /// files again and run the worker's boot steps), then a catch-up page
    /// with both links applies only the common prefix. Before the fix load
    /// reconciliation dropped the active ATA (its head was still its
    /// `from`), the gate that needs both ATAs was gone, and the page
    /// applied past the conflict. Inert.
    #[tokio::test]
    async fn a_conflict_keeps_its_bound_across_a_restart() -> anyhow::Result<()> {
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, base, links, events, owner) = conflict_fixture(&state).await?;
        let stable = base.stable_group_id().to_string();
        let restarted = super::super::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&state.agent),
        )
        .await?;
        drop(state);
        load_sidecars(&restarted).await;
        reconcile_loaded_atas(&restarted).await;
        resume_journals(&restarted).await;
        ensure_placeholders(&restarted).await;
        assert_eq!(
            head_of(&restarted, &key).await,
            Some(base.state_hash.clone()),
            "no link applied before the restart"
        );
        deliver_page(&restarted, &key, owner.agent_id(), events).await;
        assert_eq!(
            head_of(&restarted, &key).await,
            Some(links[0].commit.state_hash.clone()),
            "after the restart nothing past the common prefix applies (base {}, second link {})",
            base.state_hash,
            links[1].commit.state_hash
        );
        let body = sidecar_on_disk(&restarted, &stable).await?;
        assert!(body.attestation_conflict.is_some());
        assert!(
            body.active_ata.is_some(),
            "the conflict's ATA stays until a re-seat"
        );
        Ok(())
    }

    /// #1533 r8 Codex P1 3 (ADR 0109 §2 "Conflict", §4): at start, traffic
    /// can arrive before the sidecars are loaded. The restarted state uses
    /// the daemon's runtime (`awaiting_restore`), and both links arrive by
    /// DM before the restore runs. The gate holds them until the restore,
    /// then only the common prefix applies. Before the fix the gate read an
    /// empty sidecar map and applied both links. Inert.
    #[tokio::test]
    async fn traffic_before_the_restore_keeps_the_conflict_bound() -> anyhow::Result<()> {
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, base, links, events, owner) = conflict_fixture(&state).await?;
        let mut restarted = super::super::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&state.agent),
        )
        .await?;
        drop(state);
        Arc::get_mut(&mut restarted)
            .ok_or_else(|| anyhow::anyhow!("the fresh state is not shared yet"))?
            .group_recovery = S3Runtime::awaiting_restore();
        assert_eq!(
            head_of(&restarted, &key).await,
            Some(base.state_hash.clone())
        );

        let delivery = {
            let restarted = Arc::clone(&restarted);
            let sender = owner.agent_id();
            tokio::spawn(async move {
                for event in events {
                    let _ = super::super::apply_named_group_metadata_event(
                        &restarted, event, sender, true, None,
                    )
                    .await;
                }
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !delivery.is_finished(),
            "the gate holds the delivery until the restore"
        );
        assert_eq!(
            head_of(&restarted, &key).await,
            Some(base.state_hash.clone()),
            "no link applied before the restore"
        );
        restore_containment(&restarted).await;
        delivery.await?;
        assert_eq!(
            head_of(&restarted, &key).await,
            Some(links[0].commit.state_hash.clone()),
            "only the common prefix applies (base {}, second link {})",
            base.state_hash,
            links[1].commit.state_hash
        );
        Ok(())
    }

    /// A contained record for G4/G5: `signer` (the owner, an Active
    /// admin) committed a rename after `base`; this node holds a marker on
    /// that commit and a verified ATA whose one-link segment ends at it.
    async fn marker_fixture(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(String, GroupInfo, AdminTerminalAttestation)> {
        let local = local_hex(state);
        let signer = x0x::identity::AgentKeypair::generate()?;
        let signer_hex = hex::encode(signer.agent_id().as_bytes());
        let mut base = GroupInfo::new(
            "adr0109-marker-retire".to_string(),
            String::new(),
            signer.agent_id(),
            "7109".repeat(16),
        );
        base.add_member(
            local.clone(),
            x0x::groups::GroupRole::Member,
            Some(signer_hex.clone()),
            None,
        );
        base.seal_commit(&signer, 1_000)?;
        let mut info = base.clone();
        info.name = "renamed".to_string();
        info.seal_commit(&signer, 2_000)?;
        let links = links_after(&base, &info);
        info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: info.state_revision,
            state_hash: info.state_hash.clone(),
            committed_by: signer_hex,
            observed_at_ms: now_ms(),
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: info.terminal_commit_header(),
                conflicting_commit: info.terminal_commit_header(),
                classification: None,
            },
            no_anchor: false,
        });
        let key = info.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let ata = sign_ata(&signer, &local, &base, &links)?;
        let kept = ata.clone();
        assert!(
            update_sidecar(state, info.stable_group_id(), move |body| body.active_ata =
                Some(kept))
            .await
        );
        Ok((key, info, ata))
    }

    async fn live_marker(state: &AppState, key: &str) -> bool {
        state
            .named_groups
            .read()
            .await
            .get(key)
            .is_some_and(|info| info.fork_quarantine.is_some())
    }

    async fn disk_marker(state: &AppState, key: &str) -> anyhow::Result<bool> {
        Ok(legacy_entry(&state.named_groups_path, key)
            .await?
            .is_some_and(|info| info.fork_quarantine.is_some()))
    }

    /// Codex P1 G4 (#1533 round 3), ADR 0109 §4 "S3 publishes to the live
    /// map only when both writes are Durable": a marker retirement whose
    /// write lands but whose directory fsync fails keeps the marker, in
    /// memory and in the visible file, and retires on a later durable
    /// write.
    #[tokio::test]
    async fn marker_retirement_with_a_failed_directory_fsync_keeps_the_marker() -> anyhow::Result<()>
    {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _ata) = marker_fixture(&state).await?;
        let fault = super::super::set_save_fault(
            &state,
            super::super::SaveFault::ReplacedNotDurableAfterWrite,
        );
        assert!(!retire_marker_attested(&state, &key, &info).await);
        drop(fault);
        assert!(
            live_marker(&state, &key).await,
            "ReplacedNotDurable publishes nothing: the live record stays contained"
        );
        assert!(
            disk_marker(&state, &key).await?,
            "the visible file holds the marker again"
        );
        // The retry is durable, and only then is the marker gone.
        assert!(retire_marker_attested(&state, &key, &info).await);
        assert!(!live_marker(&state, &key).await);
        assert!(!disk_marker(&state, &key).await?);
        Ok(())
    }

    /// #1533 review: the marker retirement decides on a snapshot, so its
    /// write checks the retirement rule again on the record it changes.
    /// Before the fix the write checked only the marker's identity, and a
    /// record restored after the snapshot (same marker, evidenced commit
    /// not applied) lost its marker. Inert.
    #[tokio::test]
    async fn a_marker_retirement_rechecks_the_record_it_writes() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _ata) = marker_fixture(&state).await?;
        // After the snapshot, the live record changes to one with the same
        // marker and without its evidenced commit (a re-seat rollback
        // restores such an original).
        let marker = info
            .fork_quarantine
            .clone()
            .expect("the fixture is contained");
        let mut restored = info.clone();
        restored.commit_log.retain(|entry| {
            !(entry.commit.revision == marker.revision
                && entry.commit.state_hash == marker.state_hash)
        });
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), restored);
        assert!(!retire_marker_attested(&state, &key, &info).await);
        assert!(live_marker(&state, &key).await, "the marker stays");
        Ok(())
    }

    /// Codex P2 G5 (#1533 round 3), ADR 0109 §2 "Retirement": the terminal
    /// cleanup retires the matching marker before it deletes the ATA (the
    /// marker's retirement needs it). A restart between the two steps
    /// still retires the ATA.
    #[tokio::test]
    async fn terminal_retirement_retires_the_marker_before_the_ata() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        retire_converged(&state, &key).await;
        assert!(!live_marker(&state, &key).await, "the marker is retired");
        assert!(!disk_marker(&state, &key).await?);
        assert!(sidecar_snapshot(&state, &stable)
            .await
            .is_none_or(|body| body.active_ata.is_none()));

        // A crash after the durable marker retirement, before the ATA is
        // deleted: the reloaded ATA still matches the head and retires.
        let (state, dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(retire_marker_attested(&state, &key, &info).await);
        let reloaded = super::super::load_named_groups_merged(
            &state.named_groups_path,
            &state.home_suite_groups_path,
        )
        .await?;
        *state.named_groups.write().await = reloaded;
        state.group_recovery.inner.lock().await.sidecars.clear();
        load_sidecars(&state).await;
        reconcile_loaded_atas(&state).await;
        assert!(!live_marker(&state, &key).await);
        assert!(sidecar_snapshot(&state, &stable)
            .await
            .is_some_and(|body| body.active_ata.is_some()));
        retire_converged(&state, &key).await;
        assert!(sidecar_snapshot(&state, &stable)
            .await
            .is_none_or(|body| body.active_ata.is_none()));
        drop(dir);
        Ok(())
    }

    /// A diverging ATA for `ata`'s head: the same fields with another
    /// sequence. The sidecar checks below never verify it.
    fn diverging(ata: &AdminTerminalAttestation) -> AdminTerminalAttestation {
        let mut other = ata.clone();
        other.fields.sequence = vec!["x1".to_string()];
        other
    }

    /// #1533 r11 Codex P1 (retirement can disable a recorded conflict):
    /// a reply records a conflict after `retire_converged` read its
    /// snapshot (here: while the retirement retires the marker and waits
    /// for the sidecar writer). The retirement re-checks inside the
    /// serialized write, so the conflict keeps its ATA and its bound.
    /// Before the fix the ATA was cleared and the conflict bounded
    /// nothing. Inert.
    #[tokio::test]
    async fn a_conflict_recorded_during_retirement_keeps_its_ata() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let conflict = diverging(&ata);
        let writer = state.group_recovery.writer.lock().await;
        let task = tokio::spawn({
            let state = Arc::clone(&state);
            let key = key.clone();
            async move { retire_converged(&state, &key).await }
        });
        // The marker retires after the snapshot and before the sidecar
        // write, so its retirement shows the snapshot was read.
        for _ in 0..500 {
            if !live_marker(&state, &key).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !live_marker(&state, &key).await,
            "the retirement read its snapshot"
        );
        state
            .group_recovery
            .inner
            .lock()
            .await
            .sidecars
            .get_mut(&stable)
            .ok_or_else(|| anyhow::anyhow!("the sidecar"))?
            .attestation_conflict = Some(conflict.clone());
        drop(writer);
        task.await?;
        let body = sidecar_snapshot(&state, &stable)
            .await
            .ok_or_else(|| anyhow::anyhow!("the sidecar stays"))?;
        assert_eq!(body.active_ata, Some(ata), "the conflict keeps its ATA");
        assert_eq!(body.attestation_conflict, Some(conflict));
        Ok(())
    }

    /// #1533 rc17 (Codex P2 at 8459714): the marker retirement checks for a
    /// conflict and then clears the marker. A conflict recorded between
    /// the two (here while the clear waits for the roster write) must keep
    /// the marker. The retirement now holds the membership lock that
    /// [`record_conflict`] takes, so the record waits until the clear is
    /// done. Before the fix the record landed in the window and the marker
    /// was cleared under it. Inert.
    #[tokio::test]
    async fn a_conflict_cannot_land_between_the_retirement_check_and_clear() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = marker_fixture(&state).await?;
        let persistence = state.named_groups_persistence_lock.lock().await;
        let task = tokio::spawn({
            let state = Arc::clone(&state);
            let key = key.clone();
            let info = info.clone();
            async move { retire_marker_attested(&state, &key, &info).await }
        });
        // Let the retirement pass its checks and wait on the roster write.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let lock = super::super::group_membership_lock(&state, &key).await;
        let recorded_in_window =
            match tokio::time::timeout(Duration::from_millis(300), lock.lock()).await {
                Ok(guard) => {
                    assert!(live_marker(&state, &key).await, "the clear has not run");
                    record_conflict_locked(&state, &key, &info, diverging(&ata)).await;
                    drop(guard);
                    true
                }
                Err(_) => false,
            };
        drop(persistence);
        let retired = task.await?;
        if recorded_in_window {
            assert!(
                live_marker(&state, &key).await,
                "a conflict recorded before the clear keeps the marker"
            );
        }
        assert!(
            !recorded_in_window,
            "the record waits for the retirement to finish"
        );
        assert!(retired, "with no conflict the marker retires");
        Ok(())
    }

    /// #1533 r11: a conflict without its active ATA has no common prefix,
    /// so it admits nothing past the head (it admitted everything before).
    /// A conflict whose ATA was retired before it could be recorded is not
    /// recorded at all. Inert.
    #[tokio::test]
    async fn a_conflict_never_stands_without_its_ata() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(update_sidecar(&state, &stable, |body| body.active_ata = None).await);
        record_conflict(&state, &key, &info, diverging(&ata)).await;
        assert!(
            sidecar_snapshot(&state, &stable)
                .await
                .is_none_or(|body| body.attestation_conflict.is_none()),
            "no conflict is recorded without the ATA it diverges from"
        );

        let orphan = diverging(&ata);
        assert!(
            update_sidecar(&state, &stable, move |body| body.attestation_conflict =
                Some(orphan))
            .await
        );
        let mut commit = info.terminal_commit_header();
        commit.revision = info.state_revision + 1;
        commit.prev_state_hash = Some(info.state_hash.clone());
        commit.state_hash = ata.fields.sequence.first().cloned().unwrap_or_default();
        assert!(
            !conflict_admits_commit(&state, &info, &commit).await,
            "a conflict without its ATA admits nothing past the head"
        );
        Ok(())
    }

    /// #1533 rc18 Codex P1 (ADR 0109 §2 "Conflict"): with the head off the
    /// active ATA's chain, a recorded conflict admits no commit past the
    /// head, and the record stays placeheld. Before the fix the gate failed
    /// open: every next commit applied. Inert.
    #[tokio::test]
    async fn a_conflict_admits_nothing_from_an_off_chain_head() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (_key, info, ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let conflict = diverging(&ata);
        let active = ata.clone();
        assert!(
            update_sidecar(&state, &stable, move |body| {
                body.active_ata = Some(active);
                body.attestation_conflict = Some(conflict);
            })
            .await
        );
        let mut off = info.clone();
        off.state_hash = "off-chain-head".to_string();
        let mut commit = off.terminal_commit_header();
        commit.revision = off.state_revision + 1;
        commit.prev_state_hash = Some(off.state_hash.clone());
        for next in [
            ata.fields.sequence.first().cloned().unwrap_or_default(),
            "any-other-hash".to_string(),
        ] {
            commit.state_hash = next.clone();
            assert!(
                !conflict_admits_commit(&state, &off, &commit).await,
                "an off-chain head admitted {next}"
            );
        }
        let body = sidecar_snapshot(&state, &stable)
            .await
            .ok_or_else(|| anyhow::anyhow!("sidecar"))?;
        assert!(
            needs_placeholder(&state, &off, &body).await,
            "the conflict keeps the record placeheld"
        );
        Ok(())
    }

    /// #1533 r11: an arming whose legacy write is dropped withdraws only
    /// its own ATA, and never one that a recorded conflict holds. Inert.
    #[tokio::test]
    async fn a_dropped_arming_keeps_a_conflict_and_another_ata() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (_key, info, ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let conflict = diverging(&ata);
        let kept = conflict.clone();
        assert!(
            update_sidecar(&state, &stable, move |body| body.attestation_conflict =
                Some(kept))
            .await
        );
        assert!(!finish_arm(&state, &stable, LegacyWrite::Dropped, &ata).await);
        let body = sidecar_snapshot(&state, &stable)
            .await
            .ok_or_else(|| anyhow::anyhow!("sidecar"))?;
        assert_eq!(
            body.active_ata,
            Some(ata.clone()),
            "the conflict keeps its ATA"
        );

        assert!(update_sidecar(&state, &stable, |body| body.attestation_conflict = None).await);
        assert!(!finish_arm(&state, &stable, LegacyWrite::Dropped, &conflict).await);
        let body = sidecar_snapshot(&state, &stable)
            .await
            .ok_or_else(|| anyhow::anyhow!("sidecar"))?;
        assert_eq!(body.active_ata, Some(ata), "another arming's ATA stays");
        Ok(())
    }

    /// The placeholder record a legacy store view holds for `key`.
    async fn legacy_entry(path: &FsPath, key: &str) -> anyhow::Result<Option<GroupInfo>> {
        let bytes = tokio::fs::read(path).await?;
        let mut map: HashMap<String, GroupInfo> = serde_json::from_slice(&bytes)?;
        Ok(map.remove(key))
    }

    async fn sidecar_on_disk(state: &AppState, stable: &str) -> anyhow::Result<GroupRecoveryV1> {
        let bytes = tokio::fs::read(sidecar_path(state, stable)).await?;
        s3::decode_sidecar(&bytes).map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// A GSS group with an admin and this node Active, durable on disk, and
    /// a verified ATA from the admin for this node's head.
    async fn armed_fixture(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(String, GroupInfo, AdminTerminalAttestation)> {
        let (key, info, ata, _admin) = armed_fixture_with_signer(state).await?;
        Ok((key, info, ata))
    }

    /// [`armed_fixture`], with the admin that signed the ATA.
    async fn armed_fixture_with_signer(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(
        String,
        GroupInfo,
        AdminTerminalAttestation,
        x0x::identity::AgentKeypair,
    )> {
        let local = local_hex(state);
        let admin = x0x::identity::AgentKeypair::generate()?;
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut info = GroupInfo::new(
            "adr0109-placeholder".to_string(),
            String::new(),
            admin.agent_id(),
            "4109".repeat(16),
        );
        info.add_member(
            local.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.seal_commit(&admin, 1_000)?;
        let key = info.mls_group_id.clone();
        // `persist_named_group_info` only replaces an existing entry; a new
        // group is inserted, then the roster is saved.
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let ata = AdminTerminalAttestation::sign(
            AtaFields {
                group: info.stable_group_id().to_string(),
                subject: local,
                attested_by: admin_hex,
                signer_public_key: hex::encode(admin.public_key().as_bytes()),
                from_revision: info.state_revision,
                from_state_hash: info.state_hash.clone(),
                sequence: vec!["a1".to_string(), "a2".to_string()],
                segment_terminal_revision: info.state_revision + 2,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &admin,
        )?;
        Ok((key, info, ata, admin))
    }

    /// Codex P1 (#1533 round 1), ADR 0109 §4: arming writes the
    /// authoritative record to the sidecar and an all-Removed placeholder
    /// to the legacy views, so a released binary (which ignores `.grecov`)
    /// loads an inert group; the new binary's loader restores the real
    /// record. Before the fix the legacy views kept the real record, and
    /// the containment the ATA represents was lost on downgrade. The armed
    /// gap is never written to `invite_lineage.anchored_gap_refusal`
    /// (David's ruling 3, 21 Oct 2026).
    #[tokio::test]
    async fn arming_writes_the_placeholder_and_its_authoritative_record() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);

        let mut legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(s3::is_s3_placeholder(&legacy));
        assert_eq!(legacy.state_hash, info.state_hash, "the chain head is kept");
        assert!(legacy
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
            .is_none());
        // What a released binary does with it: no Active seat, no admin.
        legacy.migrate_from_v1();
        assert!(!legacy.has_active_member(&local));
        assert!(legacy
            .members_v2
            .values()
            .all(|member| member.state != x0x::groups::GroupMemberState::Active));

        let body = sidecar_on_disk(&state, &stable).await?;
        let authoritative: GroupInfo = serde_json::from_slice(
            body.authoritative_record
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("authoritative record"))?,
        )?;
        assert!(authoritative.has_active_member(&local));
        let binding = body
            .authoritative_binding
            .ok_or_else(|| anyhow::anyhow!("binding"))?;
        assert_eq!(binding.before, s3::AuthoritativeHead::of(&info));
        assert_eq!(binding.after, s3::AuthoritativeHead::of(&info));
        assert!(binding.before_record.is_none());

        // The new binary's loader replaces the placeholder.
        let reloaded = super::super::load_named_groups_merged(
            &state.named_groups_path,
            &state.home_suite_groups_path,
        )
        .await?;
        let record = reloaded
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("reloaded"))?;
        assert!(record.has_active_member(&local));
        assert_eq!(record.state_hash, info.state_hash);

        // Retirement: once nothing is armed, the real record goes back to
        // the legacy views and only then leaves the sidecar.
        assert!(update_sidecar(&state, &stable, |body| body.active_ata = None).await);
        ensure_placeholders(&state).await;
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&legacy));
        assert!(legacy.has_active_member(&local));
        assert!(sidecar_snapshot(&state, &stable)
            .await
            .is_none_or(|body| body.authoritative_record.is_none()));
        Ok(())
    }

    /// ADR 0109 §4 fault cases for the legacy write of an arming transition
    /// (`ReplacedNotDurable` fault tests listed as a gap in #1533):
    /// - `ReplacedNotDurable`: nothing is published, the record stays
    ///   contained (placeheld, ATA kept) and the worker writes again;
    /// - `NotReplaced`: the candidate is dropped (no ATA, no authoritative
    ///   record) and the legacy view keeps the real record.
    #[tokio::test]
    async fn arming_legacy_write_faults_publish_nothing() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();

        state.named_groups_save_fault.store(3, Ordering::SeqCst);
        assert!(!arm_in_place(&state, &key, &info, ata.clone()).await);
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        assert!(is_placeheld(&state, &stable), "stays contained");
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(body.active_ata.is_some());
        assert!(
            body.authoritative_record.is_some(),
            "the sidecar went first"
        );
        assert!(
            view_of(&state, &stable).await.is_none(),
            "nothing published"
        );
        // The worker's retry writes the placeholder durably.
        ensure_placeholders(&state).await;
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(s3::is_s3_placeholder(&legacy));
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(|entry| !entry.legacy_pending)));

        // Back to an unarmed group, then the NotReplaced case.
        assert!(update_sidecar(&state, &stable, |body| body.active_ata = None).await);
        ensure_placeholders(&state).await;
        assert!(!is_placeheld(&state, &stable));
        state.named_groups_save_fault.store(1, Ordering::SeqCst);
        assert!(!arm_in_place(&state, &key, &info, ata).await);
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        // #1570 (29 Oct 2026 ruling): a dropped arming keeps the entry —
        // the candidate is dropped, but any owed card survives. The
        // worker pass then decides the un-placeholdering with the full
        // sidecar state and holds the card routes back until its write
        // lands the real record.
        assert!(
            is_placeheld(&state, &stable),
            "the candidate is dropped; the entry stays"
        );
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(body.active_ata.is_none());
        assert!(body.authoritative_record.is_none());
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&legacy));
        assert!(legacy.has_active_member(&local));
        // The worker pass lands the real record and completes the
        // un-placeholdering.
        ensure_placeholders(&state).await;
        assert!(!is_placeheld(&state, &stable));
        // Await the pass's detached card publishes so the test leaks
        // no task.
        let pending: Vec<tokio::task::JoinHandle<()>> = {
            let mut guard = state
                .detached_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.as_mut().map(std::mem::take).unwrap_or_default()
        };
        for task in pending {
            let _ = task.await;
        }
        Ok(())
    }

    /// #1708 review, the blocking finding: a save between a dropped arming
    /// and the next worker pass must encode the group's real record. The
    /// `Dropped` rollback clears the sidecar's authoritative record and
    /// ATA, so a placeholder written in that window has nothing behind it:
    /// an orphan that load reconciliation never repairs. Red at 4ca3d176 —
    /// the rolled-back arming's digest still matched, so the window save
    /// wrote the placeholder Durable.
    #[tokio::test]
    async fn a_save_between_a_dropped_arming_and_the_pass_writes_the_real_record(
    ) -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();

        // The arming's encode writes the sidecar record; the legacy write
        // is NotReplaced, so the arming is dropped and rolled back.
        state.named_groups_save_fault.store(1, Ordering::SeqCst);
        assert!(!arm_in_place(&state, &key, &info, ata).await);
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        let body = sidecar_snapshot(&state, &stable).await.unwrap_or_default();
        assert!(body.active_ata.is_none() && body.authoritative_record.is_none());
        // The entry stays, pending its un-placeholdering: held back for
        // the card routes, not for roster saves.
        assert!(is_placeheld(&state, &stable), "the entry stays");
        assert!(is_card_held_back(&state, &stable));
        assert!(!is_held_back(&state, &stable));

        // The save in the window, before any worker pass: the real record
        // goes Durable, and no orphan placeholder is written.
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert!(
            matches!(outcome, Ok(super::super::AtomicWriteOutcome::Durable)),
            "the window save must be durable: {outcome:?}"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("window legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&legacy), "no orphan placeholder");
        assert!(legacy.has_active_member(&local));

        // The pass completes the un-placeholdering and publishes the owed
        // card the dropped arming left.
        ensure_placeholders(&state).await;
        assert!(!is_placeheld(&state, &stable));
        let pending: Vec<tokio::task::JoinHandle<()>> = {
            let mut guard = state
                .detached_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.as_mut().map(std::mem::take).unwrap_or_default()
        };
        for task in pending {
            let _ = task.await;
        }
        Ok(())
    }

    /// #1708 review (Claude finding 2, the Codex P1): a Durable write that
    /// lands a pending un-placeholdering's real record must also commit
    /// that form. The entry survives another group's save until the
    /// worker's next pass; a re-arm in that window used to keep the older
    /// placeholder as the `committed` form, so a later failed
    /// authoritative write rolled the legacy views back over the newer
    /// durable record. Red at 4ca3d176.
    #[tokio::test]
    async fn a_rearm_after_a_durable_unplacehold_keeps_the_newer_durable_form() -> anyhow::Result<()>
    {
        use super::super::AtomicWriteOutcome;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);
        let durable = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("armed legacy entry"))?;
        assert!(s3::is_s3_placeholder(&durable));

        // The ATA retires and the live record moves ahead of the durable
        // form. The pass un-placeholds the group, but its own legacy write
        // fails, so the entry stays pending with the real record not
        // committed.
        assert!(update_sidecar(&state, &stable, |body| body.active_ata = None).await);
        {
            let mut groups = state.named_groups.write().await;
            if let Some(live) = groups.get_mut(&key) {
                live.description = "newer durable form".to_string();
            }
        }
        let legacy_path = state.named_groups_path.clone();
        tokio::fs::remove_file(&legacy_path).await?;
        tokio::fs::create_dir_all(legacy_path.join("blocked")).await?;
        ensure_placeholders(&state).await;
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(|entry| entry.unplacehold_pending)));

        // The legacy file is writable again: ANOTHER group's save lands the
        // group's real record Durable. The entry survives until the next
        // pass, and the Durable write commits the form it landed.
        tokio::fs::remove_dir_all(&legacy_path).await?;
        let other_admin = x0x::identity::AgentKeypair::generate()?;
        let mut other = GroupInfo::new(
            "adr0109-other-1708".to_string(),
            String::new(),
            other_admin.agent_id(),
            "4571".repeat(16),
        );
        other.seal_commit(&other_admin, 1_000)?;
        let other_key = other.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(other_key.clone(), other);
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert!(
            matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "the other group's save must be durable: {outcome:?}"
        );
        assert!(
            legacy_entry(&state.named_groups_path, &other_key)
                .await?
                .is_some(),
            "the other group is saved"
        );
        let landed = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("landed legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&landed));
        assert_eq!(landed.description, "newer durable form");

        // A re-arm claims the placeholder again before the worker's pass,
        // and its authoritative write then fails (the sidecar cannot be
        // written). The group keeps its last COMMITTED form — the newer
        // durable record the other group's save landed, not the superseded
        // placeholder.
        let current = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("current live record"))?;
        begin_placehold(&state, &key, &current);
        let sidecar = sidecar_path(&state, &stable);
        tokio::fs::remove_file(&sidecar).await?;
        tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert!(
            matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "the re-armed save itself lands: {outcome:?}"
        );
        assert!(is_held_back(&state, &stable));
        let kept = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("kept legacy entry"))?;
        assert!(
            !s3::is_s3_placeholder(&kept),
            "a failed authoritative write rolls no placeholder back over the newer durable record"
        );
        assert_eq!(kept.description, "newer durable form");
        assert!(kept.has_active_member(&local));

        // The sidecar is writable again: the pass retries the write and
        // completes the un-placeholdering.
        tokio::fs::remove_dir_all(&sidecar).await?;
        ensure_placeholders(&state).await;
        assert!(!is_placeheld(&state, &stable));
        let pending: Vec<tokio::task::JoinHandle<()>> = {
            let mut guard = state
                .detached_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.as_mut().map(std::mem::take).unwrap_or_default()
        };
        for task in pending {
            let _ = task.await;
        }
        let final_entry = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("final legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&final_entry));
        assert_eq!(final_entry.description, "newer durable form");
        assert!(
            sidecar_snapshot(&state, &stable)
                .await
                .is_none_or(|body| body.authoritative_record.is_none()),
            "the retired record leaves the sidecar"
        );
        Ok(())
    }

    /// #1708 review (Codex controller P1, the two-save interleaving): a
    /// save parked after its encode — holding
    /// `named_groups_persistence_lock`, its Durable commit still to come —
    /// has recorded the pending group's newer real form in `encoded`. The
    /// worker's pending step must not reset that form while the save is
    /// parked: the unfixed step ran outside the lock, so the save's
    /// Durable completion left `committed` at the older placeholder, and
    /// the worker's failed retry kept that stale rollback target — a
    /// re-arm plus a failed authoritative write then wrote the placeholder
    /// over the newer durable record. Red at 2e878ec7.
    #[tokio::test]
    async fn a_parked_save_commits_its_form_across_the_workers_pending_step() -> anyhow::Result<()>
    {
        use super::super::AtomicWriteOutcome;
        use std::sync::atomic::Ordering;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);

        // The ATA retires and the live record moves ahead of the durable
        // placeholder. The pass decides the un-placeholdering, but its own
        // legacy write fails, so the entry stays pending with the real
        // record not committed.
        assert!(update_sidecar(&state, &stable, |body| body.active_ata = None).await);
        {
            let mut groups = state.named_groups.write().await;
            if let Some(live) = groups.get_mut(&key) {
                live.description = "newer durable form".to_string();
            }
        }
        let legacy_path = state.named_groups_path.clone();
        tokio::fs::remove_file(&legacy_path).await?;
        tokio::fs::create_dir_all(legacy_path.join("blocked")).await?;
        ensure_placeholders(&state).await;
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(
                |entry| entry.unplacehold_pending && entry.encoded.is_none()
            )));

        // The first save parks after its encode (the #470 interleave hook),
        // holding the persistence lock with the group's real form recorded.
        tokio::fs::remove_dir_all(&legacy_path).await?;
        let reached = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        *state
            .named_groups_save_after_snapshot_notify
            .lock()
            .expect("save race hook poisoned") = Some((
            std::sync::Arc::clone(&reached),
            std::sync::Arc::clone(&release),
        ));
        let parked_state = std::sync::Arc::clone(&state);
        let parked =
            tokio::spawn(
                async move { super::super::save_named_groups_checked(&parked_state).await },
            );
        reached.notified().await;
        *state
            .named_groups_save_after_snapshot_notify
            .lock()
            .expect("save race hook poisoned") = None;
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(|entry| entry
                .encoded
                .as_ref()
                .is_some_and(|form| !form.placeholder))));

        // The worker's pending step runs while the save is parked. The
        // serialized transition waits for the save's commit, so the
        // recorded form survives; the unfixed step cleared it here.
        let worker_state = std::sync::Arc::clone(&state);
        let worker = tokio::spawn(async move { ensure_placeholders(&worker_state).await });
        let mut cleared = false;
        for _ in 0..256 {
            tokio::task::yield_now().await;
            if with_placeheld(&state, |placeheld| {
                placeheld
                    .get(&stable)
                    .is_some_and(|entry| entry.encoded.is_none())
            }) {
                cleared = true;
                break;
            }
        }
        // #1708 review: the negative check above is no proof on its own;
        // a worker that stalled before the pending step also keeps
        // `encoded`. The pass cannot run while the parked save holds the
        // persistence lock, so a worker that reached the step's lock (its
        // every earlier await is uncontended here) is still mid-pass.
        assert!(
            !worker.is_finished(),
            "the worker pass reached the pending step and waits on the parked save's lock"
        );
        assert!(
            !cleared,
            "the pending step must not clear a parked save's encoded form"
        );

        // The parked save completes Durable and commits the real form it
        // landed. The worker's own retry then fails (variant 6 leaves this
        // save unfaulted and degrades the next legacy write to
        // not-durable) and must not move the committed form.
        state.named_groups_save_fault.store(6, Ordering::SeqCst);
        release.notify_one();
        let outcome = parked.await.expect("parked save task panicked");
        assert!(
            matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "the parked save must be durable: {outcome:?}"
        );
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(
                |entry| entry.committed.record.description == "newer durable form"
            )));
        worker.await.expect("worker pass panicked");
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(|entry| entry.unplacehold_pending
                && entry.committed.record.description
                    == "newer durable form")));
        state.named_groups_save_fault.store(0, Ordering::SeqCst);
        let landed = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("parked legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&landed));
        assert_eq!(landed.description, "newer durable form");

        // A re-arm whose authoritative write fails keeps the newer durable
        // record — the committed form the parked save committed — never
        // the superseded placeholder.
        let current = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("current live record"))?;
        begin_placehold(&state, &key, &current);
        let sidecar = sidecar_path(&state, &stable);
        tokio::fs::remove_file(&sidecar).await?;
        tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert!(
            matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "the re-armed save itself lands: {outcome:?}"
        );
        assert!(is_held_back(&state, &stable));
        let kept = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("kept legacy entry"))?;
        assert!(
            !s3::is_s3_placeholder(&kept),
            "a failed authoritative write rolls no placeholder back over the newer durable record"
        );
        assert_eq!(kept.description, "newer durable form");
        assert!(kept.has_active_member(&local));

        // The sidecar is writable again: the pass retries the write and
        // completes the un-placeholdering.
        tokio::fs::remove_dir_all(&sidecar).await?;
        ensure_placeholders(&state).await;
        assert!(!is_placeheld(&state, &stable));
        let pending: Vec<tokio::task::JoinHandle<()>> = {
            let mut guard = state
                .detached_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.as_mut().map(std::mem::take).unwrap_or_default()
        };
        for task in pending {
            let _ = task.await;
        }
        let final_entry = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("final legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&final_entry));
        assert_eq!(final_entry.description, "newer durable form");
        assert!(
            sidecar_snapshot(&state, &stable)
                .await
                .is_none_or(|body| body.authoritative_record.is_none()),
            "the retired record leaves the sidecar"
        );
        Ok(())
    }

    /// Await the detached tasks the worker pass spawned (the owed-card
    /// publishes), so assertions below see their effects.
    async fn drain_detached(state: &Arc<AppState>) {
        let pending: Vec<tokio::task::JoinHandle<()>> = {
            let mut guard = state
                .detached_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.as_mut().map(std::mem::take).unwrap_or_default()
        };
        for task in pending {
            let _ = task.await;
        }
    }

    /// #1708 review (Claude REQUEST-CHANGES, the arming race): the pass
    /// snapshots the sidecars, then waits for the persistence lock before
    /// it resets its un-placehold list. An arming that starts in between
    /// installs its ATA, claims the placeholder and saves under the same
    /// lock. The unfixed reset flipped that armed group to pending: the
    /// pass's resave landed the real record, the retain dropped the
    /// entry, and the sidecar clear stripped the authoritative record
    /// while the ATA stayed armed, so the pass published a card for a
    /// contained group. The fixed reset re-reads each listed stable's
    /// sidecar under the lock and leaves a group whose body changed since
    /// the snapshot to the next pass. Inert.
    #[tokio::test]
    async fn an_arming_across_the_pending_step_is_not_undone() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata.clone()).await);

        // A dropped arming: the sidecar no longer arms anything and the
        // entry stays as a pending un-placeholdering that owes a card,
        // the state whose next pass races the re-arm below.
        assert!(!finish_arm(&state, &stable, LegacyWrite::Dropped, &ata).await);
        assert!(sidecar_snapshot(&state, &stable).await.is_none_or(|body| {
            body.active_ata.is_none() && body.authoritative_record.is_none()
        }));

        // The test holds the persistence lock, so the worker pass
        // snapshots the disarmed sidecar and then waits at its pending
        // step. The re-arm cannot pass the lock, so its pre-save steps
        // (the ATA install and the placeholder claim) land between the
        // pass's snapshot and its reset.
        let guard = state.named_groups_persistence_lock.lock().await;
        let worker_state = std::sync::Arc::clone(&state);
        let worker = tokio::spawn(async move { ensure_placeholders(&worker_state).await });
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The re-arm: a second ATA from the same admin for the same head.
        let ata_two = AdminTerminalAttestation::sign(
            AtaFields {
                group: stable.clone(),
                subject: local_hex(&state),
                attested_by: hex::encode(admin.agent_id().as_bytes()),
                signer_public_key: hex::encode(admin.public_key().as_bytes()),
                from_revision: info.state_revision,
                from_state_hash: info.state_hash.clone(),
                sequence: vec!["b1".to_string(), "b2".to_string()],
                segment_terminal_revision: info.state_revision + 2,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &admin,
        )?;
        let arming_state = std::sync::Arc::clone(&state);
        let arming_key = key.clone();
        let arming_info = info.clone();
        let arming = tokio::spawn(async move {
            arm_in_place(&arming_state, &arming_key, &arming_info, ata_two).await
        });
        let mut claimed = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if sidecar_snapshot(&state, &stable)
                .await
                .is_some_and(|body| body.active_ata.is_some())
                && with_placeheld(&state, |placeheld| {
                    placeheld
                        .get(&stable)
                        .is_some_and(|entry| !entry.unplacehold_pending)
                })
            {
                claimed = true;
                break;
            }
        }
        assert!(
            claimed,
            "the re-arm installed its ATA and claimed the placeholder before its save"
        );

        // The arming's save parks (the #470 interleave hook) across the
        // worker's pending step. Whichever save parks first, it holds the
        // persistence lock, so the armed group must not be flipped to
        // pending while it is parked.
        let reached = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        *state
            .named_groups_save_after_snapshot_notify
            .lock()
            .expect("save race hook poisoned") = Some((
            std::sync::Arc::clone(&reached),
            std::sync::Arc::clone(&release),
        ));
        drop(guard);
        reached.notified().await;
        *state
            .named_groups_save_after_snapshot_notify
            .lock()
            .expect("save race hook poisoned") = None;
        assert!(
            with_placeheld(&state, |placeheld| placeheld
                .get(&stable)
                .is_some_and(|entry| !entry.unplacehold_pending)),
            "the pending step must not flip a concurrently armed group"
        );
        release.notify_one();
        let published = arming.await.expect("arming task panicked");
        assert!(published, "the re-arm published");
        worker.await.expect("worker pass panicked");

        // The armed group keeps its containment: the entry survives with
        // the armed placeholder as its committed form, the sidecar keeps
        // the authoritative record and the ATA, and the legacy view holds
        // the placeholder.
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(|entry| !entry.unplacehold_pending
                && !entry.authoritative_failed
                && entry.committed.placeholder)));
        let body = sidecar_on_disk(&state, &stable).await?;
        assert!(body.active_ata.is_some(), "the re-arm's ATA stays armed");
        assert!(
            body.authoritative_record.is_some(),
            "the sidecar keeps the authoritative record of the armed group"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("armed legacy entry"))?;
        assert!(
            s3::is_s3_placeholder(&legacy),
            "the legacy view keeps the placeholder of the armed group"
        );
        Ok(())
    }

    /// #1708 review (Codex P1 at 3bed4e49, the post-reread arming): the
    /// worker holds the persistence lock and its sidecar re-read finds the
    /// group unchanged. An arming's pre-save steps (the ATA install and
    /// the placeholder claim) do not take the persistence lock, so at
    /// 3bed4e49 they could land after the re-read released its guard and
    /// before the reset, and the reset undid the claim. The fixed step
    /// holds the sidecar guard from the re-read through the reset, so the
    /// install waits and the claim comes after the reset. Red at
    /// 3bed4e49 (the hook then parks with the guard released). Inert.
    #[tokio::test]
    async fn an_arming_after_the_pending_reread_is_not_undone() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata, admin) = armed_fixture_with_signer(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata.clone()).await);
        assert!(!finish_arm(&state, &stable, LegacyWrite::Dropped, &ata).await);

        // The worker parks after its re-read of the disarmed sidecar,
        // holding the persistence lock.
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        state.group_recovery.inner.lock().await.pending_reread_pause =
            Some((Arc::clone(&reached), Arc::clone(&release)));
        let worker_state = Arc::clone(&state);
        let worker = tokio::spawn(async move { ensure_placeholders(&worker_state).await });
        reached.notified().await;
        assert!(
            state.named_groups_persistence_lock.try_lock().is_err(),
            "the worker holds the persistence lock at its pending step"
        );

        // The re-arm runs its pre-save steps in the gap.
        let ata_two = AdminTerminalAttestation::sign(
            AtaFields {
                group: stable.clone(),
                subject: local_hex(&state),
                attested_by: hex::encode(admin.agent_id().as_bytes()),
                signer_public_key: hex::encode(admin.public_key().as_bytes()),
                from_revision: info.state_revision,
                from_state_hash: info.state_hash.clone(),
                sequence: vec!["b1".to_string(), "b2".to_string()],
                segment_terminal_revision: info.state_revision + 2,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &admin,
        )?;
        let arming_state = Arc::clone(&state);
        let arming_key = key.clone();
        let arming_info = info.clone();
        let arming = tokio::spawn(async move {
            arm_in_place(&arming_state, &arming_key, &arming_info, ata_two).await
        });
        // Give the arming every chance to claim the placeholder in the gap.
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if with_placeheld(&state, |placeheld| {
                placeheld
                    .get(&stable)
                    .is_some_and(|entry| !entry.unplacehold_pending)
            }) {
                break;
            }
        }
        release.notify_one();
        worker.await.expect("worker pass panicked");
        assert!(
            arming.await.expect("arming task panicked"),
            "the re-arm published"
        );

        // The re-arm's claim stands: the armed group keeps its entry, the
        // sidecar keeps the ATA and the authoritative record, and the
        // legacy view holds the placeholder.
        assert!(
            with_placeheld(&state, |placeheld| placeheld
                .get(&stable)
                .is_some_and(|entry| !entry.unplacehold_pending)),
            "the pending reset must not undo a later arming's claim"
        );
        let body = sidecar_on_disk(&state, &stable).await?;
        assert!(body.active_ata.is_some(), "the re-arm's ATA stays armed");
        assert!(
            body.authoritative_record.is_some(),
            "the sidecar keeps the authoritative record of the armed group"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("armed legacy entry"))?;
        assert!(
            s3::is_s3_placeholder(&legacy),
            "the legacy view keeps the placeholder of the armed group"
        );
        Ok(())
    }

    /// #1708 review: a dropped arming leaves its owed card on the entry.
    /// The pass that un-placeholds the group lands the real record
    /// durably, completes the entry and must then actually publish the
    /// owed card. No test showed that end state for a dropped arming.
    /// Inert.
    #[tokio::test]
    async fn a_dropped_armings_owed_card_is_published() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata, _admin) = listable_armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata.clone()).await);
        assert!(!finish_arm(&state, &stable, LegacyWrite::Dropped, &ata).await);
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(
                |entry| entry.unplacehold_pending && entry.card_owed
            )));

        // The next pass completes the un-placeholdering with a Durable
        // write of the real record and publishes the owed card.
        ensure_placeholders(&state).await;
        drain_detached(&state).await;
        assert!(
            with_placeheld(&state, |placeheld| placeheld.get(&stable).is_none()),
            "the completed entry goes"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("recovered legacy entry"))?;
        assert!(!s3::is_s3_placeholder(&legacy));
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&stable)
            .ok_or_else(|| anyhow::anyhow!("the owed card was published"))?;
        assert_eq!(
            published.name, "issue1570 owed card fixture",
            "the publish put the committed card in the shard cache"
        );
        Ok(())
    }

    /// #1708 review: a reseal whose persist ends the hold publishes the
    /// card itself, so it also settles the owed card. Left set, the next
    /// pass published the same card again. Inert.
    #[tokio::test]
    async fn a_reseal_that_ends_the_hold_settles_the_owed_card() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        // A listable group owned by this node, like the card-route
        // fixtures.
        let key = "61".repeat(16);
        let policy = x0x::groups::GroupPolicy {
            discoverability: x0x::groups::GroupDiscoverability::PublicDirectory,
            ..Default::default()
        };
        let info = x0x::groups::GroupInfo::with_policy(
            "Issue1570ResealOwed".to_string(),
            String::new(),
            state.agent.agent_id(),
            key.clone(),
            policy,
        );
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        let durable = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("fixture group"))?;

        // Placehold the group, then block the sidecar so the next change
        // is held back and owes a card.
        begin_placehold(&state, &key, &durable);
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let sidecar = sidecar_path(&state, &stable);
        tokio::fs::remove_file(&sidecar).await?;
        tokio::fs::create_dir_all(sidecar.join("blocked")).await?;
        let mut bumped = durable.clone();
        bumped.roster_revision = bumped.roster_revision.saturating_add(1);
        bumped.seal_commit(state.agent.identity().agent_keypair(), now_ms())?;
        let outcome = super::super::persist_named_group_info(&state, &key, bumped).await;
        assert!(
            !matches!(outcome, Ok(super::super::AtomicWriteOutcome::Durable)),
            "the change is held back: {outcome:?}"
        );
        assert!(is_held_back(&state, &stable));
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(|entry| entry.card_owed)));

        // The sidecar is writable again: the reseal's own persist retries
        // it, ends the hold, commits and publishes (Engineer ruling,
        // 29 Oct 2026 19:56), and the publish settles the owed card.
        tokio::fs::remove_dir_all(&sidecar).await?;
        let resp = super::super::seal_group_state(
            State(std::sync::Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Path(key.clone()),
        )
        .await
        .into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the seal ends the hold itself: {body}"
        );
        assert!(!is_held_back(&state, &stable));
        assert!(
            with_placeheld(&state, |placeheld| placeheld
                .get(&stable)
                .is_none_or(|entry| !entry.card_owed)),
            "the reseal's publish settled the owed card"
        );
        let committed_revision = state
            .named_groups
            .read()
            .await
            .get(&key)
            .map(|current| current.state_revision)
            .ok_or_else(|| anyhow::anyhow!("group after the seal"))?;
        let directory = state.directory_cache.read().await;
        let published = directory
            .get(&stable)
            .ok_or_else(|| anyhow::anyhow!("the reseal published its card"))?;
        assert_eq!(
            published.revision, committed_revision,
            "the reseal published the card of the record it committed"
        );
        Ok(())
    }

    /// [`armed_fixture`], with a `PublicDirectory` policy: a published
    /// card of the group reaches the discovery caches.
    async fn listable_armed_fixture(
        state: &Arc<AppState>,
    ) -> anyhow::Result<(
        String,
        GroupInfo,
        AdminTerminalAttestation,
        x0x::identity::AgentKeypair,
    )> {
        let local = local_hex(state);
        let admin = x0x::identity::AgentKeypair::generate()?;
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let policy = x0x::groups::GroupPolicy {
            discoverability: x0x::groups::GroupDiscoverability::PublicDirectory,
            ..Default::default()
        };
        let mut info = x0x::groups::GroupInfo::with_policy(
            "issue1570 owed card fixture".to_string(),
            String::new(),
            admin.agent_id(),
            "5157".repeat(16),
            policy,
        );
        info.add_member(
            local.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
        info.seal_commit(&admin, 1_000)?;
        let key = info.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let ata = AdminTerminalAttestation::sign(
            AtaFields {
                group: info.stable_group_id().to_string(),
                subject: local,
                attested_by: hex::encode(admin.agent_id().as_bytes()),
                signer_public_key: hex::encode(admin.public_key().as_bytes()),
                from_revision: info.state_revision,
                from_state_hash: info.state_hash.clone(),
                sequence: vec!["c1".to_string()],
                segment_terminal_revision: info.state_revision + 1,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &admin,
        )?;
        Ok((key, info, ata, admin))
    }

    /// ADR 0109 §4 "sidecar, then legacy view": when the authoritative
    /// record cannot be made durable, a placeholder is never on disk
    /// without its backing. #1570: the group keeps its real record in the
    /// legacy views and its arming is dropped; the save itself is not
    /// blocked.
    #[tokio::test]
    async fn placeholder_is_never_written_without_a_durable_authoritative_record(
    ) -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let (key, info, _ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        // The sidecar directory cannot be created: a file holds its name.
        tokio::fs::write(sidecar_dir(&state), b"not a directory").await?;
        begin_placehold(&state, &key, &info);
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert_eq!(
            confirm_placeheld_write(&state, &stable, LegacyWrite::of(&outcome)),
            LegacyWrite::Dropped,
            "the arming is not published"
        );
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
        assert!(
            !s3::is_s3_placeholder(&legacy),
            "no placeholder without backing"
        );
        assert!(legacy.has_active_member(&local));
        Ok(())
    }

    /// #1570: while one placeheld group's sidecar cannot be written, the
    /// roster saves of every other group still land. The blocked group
    /// keeps the placeholder of its durable authoritative record (its
    /// containment), its change is held back, and the worker writes it
    /// once the sidecar is writable again. Before the fix every roster
    /// save failed while the sidecar was unwritable.
    #[tokio::test]
    async fn an_unwritable_sidecar_holds_back_only_its_own_group() -> anyhow::Result<()> {
        use super::super::AtomicWriteOutcome;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);
        let durable = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("armed legacy entry"))?;
        assert!(s3::is_s3_placeholder(&durable));

        // The armed group's sidecar cannot be written: a non-empty
        // directory holds its name.
        let path = sidecar_path(&state, &stable);
        tokio::fs::remove_file(&path).await?;
        tokio::fs::create_dir_all(path.join("blocked")).await?;

        // The armed group's live record changes, so the next save must
        // write its authoritative record again; another group is added.
        let other_admin = x0x::identity::AgentKeypair::generate()?;
        let mut other = GroupInfo::new(
            "adr0109-other".to_string(),
            String::new(),
            other_admin.agent_id(),
            "4570".repeat(16),
        );
        other.seal_commit(&other_admin, 1_000)?;
        let other_key = other.mls_group_id.clone();
        {
            let mut groups = state.named_groups.write().await;
            if let Some(live) = groups.get_mut(&key) {
                live.description = "changed while blocked".to_string();
            }
            groups.insert(other_key.clone(), other);
        }
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert!(
            matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "another group's save is not blocked: {outcome:?}"
        );
        assert!(
            legacy_entry(&state.named_groups_path, &other_key)
                .await?
                .is_some(),
            "the other group is saved"
        );
        let held = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("held legacy entry"))?;
        assert_eq!(
            serde_json::to_value(&held)?,
            serde_json::to_value(&durable)?,
            "the blocked group keeps its durable placeholder"
        );
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(
                |entry| entry.authoritative_failed && entry.legacy_pending
            )));
        assert_eq!(
            confirm_placeheld_write(&state, &stable, LegacyWrite::of(&outcome)),
            LegacyWrite::ReplacedNotDurable,
            "the blocked group's change is not published as durable"
        );

        // The sidecar is writable again: the worker writes the change.
        tokio::fs::remove_dir_all(&path).await?;
        ensure_placeholders(&state).await;
        let legacy = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("rewritten legacy entry"))?;
        assert!(s3::is_s3_placeholder(&legacy));
        assert_eq!(legacy.description, "changed while blocked");
        let record = sidecar_on_disk(&state, &stable)
            .await?
            .authoritative_record
            .ok_or_else(|| anyhow::anyhow!("authoritative record"))?;
        let record: GroupInfo = serde_json::from_slice(&record)?;
        assert_eq!(record.description, "changed while blocked");
        assert!(with_placeheld(&state, |placeheld| placeheld
            .get(&stable)
            .is_some_and(
                |entry| !entry.authoritative_failed && !entry.legacy_pending
            )));
        Ok(())
    }

    /// #1570 review: a held-back group keeps its last durable form under
    /// every key that holds it, not only under its canonical key. An alias
    /// key keeps the placeholder of the durable authoritative record, not
    /// a placeholder of the changed live record that has no backing.
    #[tokio::test]
    async fn an_unwritable_sidecar_keeps_every_alias_in_its_durable_form() -> anyhow::Result<()> {
        use super::super::AtomicWriteOutcome;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let alias = format!("{key}-alias");
        state
            .named_groups
            .write()
            .await
            .insert(alias.clone(), info.clone());
        assert!(arm_in_place(&state, &key, &info, ata).await);
        let durable = legacy_entry(&state.named_groups_path, &alias)
            .await?
            .ok_or_else(|| anyhow::anyhow!("armed alias entry"))?;
        assert!(s3::is_s3_placeholder(&durable));

        let path = sidecar_path(&state, &stable);
        tokio::fs::remove_file(&path).await?;
        tokio::fs::create_dir_all(path.join("blocked")).await?;
        {
            let mut groups = state.named_groups.write().await;
            for spelling in [&key, &alias] {
                if let Some(live) = groups.get_mut(spelling.as_str()) {
                    live.description = "changed while blocked".to_string();
                }
            }
        }
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert!(matches!(outcome, Ok(AtomicWriteOutcome::Durable)));
        for spelling in [&key, &alias] {
            let held = legacy_entry(&state.named_groups_path, spelling)
                .await?
                .ok_or_else(|| anyhow::anyhow!("held legacy entry"))?;
            assert_eq!(
                serde_json::to_value(&held)?,
                serde_json::to_value(&durable)?,
                "{spelling} keeps the durable placeholder"
            );
        }
        Ok(())
    }

    /// #1570 review: before any authoritative record is durable, a failed
    /// authoritative write keeps the real record under every key of the
    /// group. No alias gets a placeholder that has no backing.
    #[tokio::test]
    async fn a_held_back_alias_never_gets_a_placeholder_without_backing() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        let alias = format!("{key}-alias");
        state
            .named_groups
            .write()
            .await
            .insert(alias.clone(), info.clone());
        tokio::fs::write(sidecar_dir(&state), b"not a directory").await?;
        begin_placehold(&state, &key, &info);
        let outcome = super::super::save_named_groups_checked(&state).await;
        assert_eq!(
            confirm_placeheld_write(&state, &stable, LegacyWrite::of(&outcome)),
            LegacyWrite::Dropped
        );
        for spelling in [&key, &alias] {
            let legacy = legacy_entry(&state.named_groups_path, spelling)
                .await?
                .ok_or_else(|| anyhow::anyhow!("legacy entry"))?;
            assert!(
                !s3::is_s3_placeholder(&legacy),
                "{spelling}: no placeholder without backing"
            );
        }
        Ok(())
    }

    /// #1570 review, ADR 0109 §4 "publish only when both are durable": a
    /// per-group save of a held-back group does not report `Durable` while
    /// the group's authoritative write failed. Once the sidecar is
    /// writable again, the same save is `Durable`.
    #[tokio::test]
    async fn a_held_back_group_save_is_not_reported_durable() -> anyhow::Result<()> {
        use super::super::AtomicWriteOutcome;
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);

        let path = sidecar_path(&state, &stable);
        tokio::fs::remove_file(&path).await?;
        tokio::fs::create_dir_all(path.join("blocked")).await?;
        let mut next = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("live record"))?;
        next.description = "changed while blocked".to_string();
        let outcome = super::super::persist_named_group_info(&state, &key, next.clone()).await;
        assert!(
            !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "the authoritative write failed, so the save is not durable: {outcome:?}"
        );

        tokio::fs::remove_dir_all(&path).await?;
        next.description = "changed after unblock".to_string();
        let outcome = super::super::persist_named_group_info(&state, &key, next).await;
        assert!(
            matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "both writes are durable: {outcome:?}"
        );
        Ok(())
    }

    /// Block `stable`'s sidecar (a non-empty directory holds its name),
    /// change the live record under `key` and save: the group is held
    /// back.
    async fn hold_back_by_blocked_sidecar(
        state: &Arc<AppState>,
        key: &str,
        stable: &str,
        note: &str,
    ) -> anyhow::Result<()> {
        let path = sidecar_path(state, stable);
        if tokio::fs::metadata(&path).await.is_ok_and(|m| m.is_file()) {
            tokio::fs::remove_file(&path).await?;
        }
        tokio::fs::create_dir_all(path.join("blocked")).await?;
        if let Some(live) = state.named_groups.write().await.get_mut(key) {
            live.description = note.to_string();
        }
        super::super::save_named_groups_checked(state).await?;
        assert!(
            is_held_back(state, stable),
            "{note}: the group is held back"
        );
        Ok(())
    }

    /// ZCode on d1be57f1 (#1570), the #1645 swap rollback: a Durable
    /// restore of `named_groups.json` puts each placeheld group's committed
    /// legacy form back with the bytes. Here a Durable save commits v2 of
    /// group P, the restore puts the v1 bytes back, and then P is held
    /// back. RED (before the fix): the held-back save wrote P's v2 form,
    /// which the restore had removed from disk. GREEN: it writes v1, the
    /// form on disk. (In the swap itself the rollback runs only when the
    /// swap's legacy write did not land Durable, so no commit is undone
    /// today; this pins the restore's own contract.) Inert.
    #[tokio::test]
    async fn a_roster_restore_puts_the_committed_form_back() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);
        let v1 = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("armed legacy entry"))?;
        assert!(s3::is_s3_placeholder(&v1));
        let before = super::super::read_roster_stores(&state).await?;

        // A Durable save commits P's v2 form.
        if let Some(live) = state.named_groups.write().await.get_mut(&key) {
            live.description = "v2".to_string();
        }
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        // The rollback puts the v1 bytes back.
        super::super::restore_named_store(&state, &before).await?;
        let restored = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("restored legacy entry"))?;
        assert_eq!(serde_json::to_value(&restored)?, serde_json::to_value(&v1)?);

        // P is held back: its legacy entry must stay the form on disk (v1).
        hold_back_by_blocked_sidecar(&state, &key, &stable, "v3").await?;
        let held = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("held legacy entry"))?;
        assert_eq!(
            serde_json::to_value(&held)?,
            serde_json::to_value(&v1)?,
            "#1570: the held-back form is the restored one, not the undone v2"
        );
        Ok(())
    }

    /// ZCode on d1be57f1 (#1570): an encode clears the held-back latch of
    /// a placeheld group that has no authoritative write in it: a group
    /// that is lost, absent from the map, or frozen for a staged re-seat.
    /// If a branch kept the latch, `is_held_back` would stay true for
    /// ever, and every later change to the group would be refused (fail
    /// closed, but a permanent stall). The sidecar stays unwritable in
    /// each step, so only the branch can clear the latch. Inert.
    #[tokio::test]
    async fn the_held_back_latch_clears_for_lost_absent_and_frozen_groups() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, ata) = armed_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert!(arm_in_place(&state, &key, &info, ata).await);
        assert!(!is_held_back(&state, &stable));

        // Lost: load reconciliation kept an inert placeholder.
        hold_back_by_blocked_sidecar(&state, &key, &stable, "lost").await?;
        with_placeheld(&state, |placeheld| {
            if let Some(entry) = placeheld.get_mut(&stable) {
                entry.lost = true;
            }
        });
        super::super::save_named_groups_checked(&state).await?;
        assert!(
            !is_held_back(&state, &stable),
            "a lost group is not held back"
        );
        with_placeheld(&state, |placeheld| {
            if let Some(entry) = placeheld.get_mut(&stable) {
                entry.lost = false;
            }
        });

        // Absent: the group has no record in the map.
        hold_back_by_blocked_sidecar(&state, &key, &stable, "absent").await?;
        let live = state
            .named_groups
            .write()
            .await
            .remove(&key)
            .ok_or_else(|| anyhow::anyhow!("live record"))?;
        super::super::save_named_groups_checked(&state).await?;
        assert!(
            !is_held_back(&state, &stable),
            "an absent group is not held back"
        );
        state.named_groups.write().await.insert(key.clone(), live);

        // Frozen: a staged re-seat keeps the original's record. The journal
        // is written while the sidecar is writable, then it is blocked
        // again.
        hold_back_by_blocked_sidecar(&state, &key, &stable, "frozen").await?;
        let path = sidecar_path(&state, &stable);
        tokio::fs::remove_dir_all(&path).await?;
        let original = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("live record"))?;
        assert!(open_staging_journal_for_test(&state, &key, &original).await?);
        assert!(
            is_held_back(&state, &stable),
            "a journal write keeps the latch"
        );
        tokio::fs::remove_file(&path).await?;
        tokio::fs::create_dir_all(path.join("blocked")).await?;
        super::super::save_named_groups_checked(&state).await?;
        assert!(
            !is_held_back(&state, &stable),
            "a frozen group is not held back"
        );
        Ok(())
    }

    /// Codex P1 on #1646 (#1570), ADR 0109 §4 "publish only when both are
    /// durable": a marker retirement of a placeheld group whose sidecar
    /// cannot be written is not published. The encode holds the group
    /// back, so its legacy entry keeps the marked placeholder. Before the
    /// fix the legacy write was `Durable`, the cleared record went to the
    /// live map, and task ingest resumed with no durable clear behind it.
    /// Once the sidecar is writable again, the retry retires the marker.
    /// Inert.
    #[tokio::test]
    async fn marker_retirement_is_not_published_while_its_sidecar_write_fails() -> anyhow::Result<()>
    {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        // The contained group is placeheld, with a durable authoritative
        // record that holds the marker.
        begin_placehold(&state, &key, &info);
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        assert!(is_placeheld(&state, &stable));
        assert!(!is_held_back(&state, &stable));
        let durable = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("placeheld legacy entry"))?;
        assert!(s3::is_s3_placeholder(&durable));
        assert!(durable.fork_quarantine.is_some());

        // The group's sidecar cannot be written: a non-empty directory
        // holds its name. The retirement clears the marker, so the record
        // differs from the durable one and must be written again.
        let path = sidecar_path(&state, &stable);
        tokio::fs::remove_file(&path).await?;
        tokio::fs::create_dir_all(path.join("blocked")).await?;
        assert!(
            !retire_marker_attested(&state, &key, &info).await,
            "the clear is not durable, so it is not published"
        );
        assert!(is_held_back(&state, &stable));
        assert!(
            live_marker(&state, &key).await,
            "the live record stays contained"
        );
        let held = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("held legacy entry"))?;
        assert_eq!(
            serde_json::to_value(&held)?,
            serde_json::to_value(&durable)?,
            "the legacy file keeps the marked placeholder"
        );
        let backing = state
            .group_recovery
            .inner
            .lock()
            .await
            .sidecars
            .get(&stable)
            .and_then(|body| body.authoritative_record.clone())
            .ok_or_else(|| anyhow::anyhow!("authoritative record"))?;
        let backing: GroupInfo = serde_json::from_slice(&backing)?;
        assert!(
            backing.fork_quarantine.is_some(),
            "the authoritative record still holds the marker"
        );
        assert!(is_placeheld(&state, &stable), "the group stays placeheld");

        // The sidecar is writable again: the retry is durable, and only
        // then is the marker gone.
        tokio::fs::remove_dir_all(&path).await?;
        assert!(retire_marker_attested(&state, &key, &info).await);
        assert!(!is_held_back(&state, &stable));
        assert!(!live_marker(&state, &key).await);
        assert!(!disk_marker(&state, &key).await?);
        let record = sidecar_on_disk(&state, &stable)
            .await?
            .authoritative_record
            .ok_or_else(|| anyhow::anyhow!("authoritative record on disk"))?;
        let record: GroupInfo = serde_json::from_slice(&record)?;
        assert!(record.fork_quarantine.is_none());
        Ok(())
    }

    /// Codex P1 on #1646 (#1570 rc4), ADR 0109 §4 "publish only when both
    /// are durable" and "Crash reconciliation at load": a quarantine clear
    /// of a placeheld group writes its cleared record to the sidecar, but
    /// its legacy write fails. A later save then cannot write the sidecar,
    /// so the group is held back. The held-back legacy entry must be the
    /// last committed form (the marked placeholder), not the placeholder of
    /// the failed clear. Before the fix the encode used the sidecar's
    /// latest record (the cleared one). At restart the splice matched that
    /// placeholder to the binding's `after` and loaded the cleared record:
    /// the quarantine was lost. Inert.
    #[tokio::test]
    async fn a_failed_clear_is_never_the_held_back_form_after_restart() -> anyhow::Result<()> {
        use super::super::{AtomicWriteOutcome, SaveFault};
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _ata) = marker_fixture(&state).await?;
        let stable = info.stable_group_id().to_string();
        // The contained group is placeheld, with a durable authoritative
        // record that holds the marker.
        begin_placehold(&state, &key, &info);
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            AtomicWriteOutcome::Durable
        ));
        assert!(is_placeheld(&state, &stable));
        assert!(!is_held_back(&state, &stable));
        let committed = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("placeheld legacy entry"))?;
        assert!(s3::is_s3_placeholder(&committed));
        assert!(committed.fork_quarantine.is_some());

        // The clear: its sidecar write lands, its legacy write fails.
        let fault = super::super::set_save_fault(&state, SaveFault::Error);
        let clear_key = key.clone();
        let outcome = super::super::persist_named_groups_quarantine_clear_durable_only(
            &state,
            move |groups| {
                let Some(info) = groups.get_mut(&clear_key) else {
                    return false;
                };
                info.fork_quarantine = None;
                info.reset_fork_evidence_after_quarantine_clear();
                true
            },
        )
        .await;
        drop(fault);
        assert!(
            !matches!(outcome, Ok(AtomicWriteOutcome::Durable)),
            "the legacy write failed, so the clear is not durable: {outcome:?}"
        );
        assert!(
            live_marker(&state, &key).await,
            "the live record stays contained"
        );
        let sidecar = sidecar_on_disk(&state, &stable).await?;
        let latest: GroupInfo = serde_json::from_slice(
            sidecar
                .authoritative_record
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("authoritative record on disk"))?,
        )?;
        assert!(
            latest.fork_quarantine.is_none(),
            "precondition: the sidecar's latest record is the failed clear"
        );
        assert_eq!(
            serde_json::to_value(
                legacy_entry(&state.named_groups_path, &key)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("legacy entry after the clear"))?
            )?,
            serde_json::to_value(&committed)?,
            "the failed legacy write left the committed form in place"
        );

        // Keep the sidecar bytes (binding before = committed, after =
        // cleared), then make the sidecar unwritable for a later save.
        let path = sidecar_path(&state, &stable);
        let kept = tokio::fs::read(&path).await?;
        tokio::fs::remove_file(&path).await?;
        tokio::fs::create_dir_all(path.join("blocked")).await?;
        let _later = super::super::save_named_groups_checked(&state).await;
        assert!(is_held_back(&state, &stable), "the later save holds back");
        let held = legacy_entry(&state.named_groups_path, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("held legacy entry"))?;
        assert!(s3::is_s3_placeholder(&held));
        assert!(
            held.fork_quarantine.is_some(),
            "the held-back legacy entry keeps the marker"
        );
        assert_eq!(
            serde_json::to_value(&held)?,
            serde_json::to_value(&committed)?,
            "the held-back legacy entry is the last committed form"
        );

        // Restart: the sidecar holds its last written bytes. The splice
        // must load a contained record.
        tokio::fs::remove_dir_all(&path).await?;
        tokio::fs::write(&path, &kept).await?;
        let reloaded = super::super::load_named_groups_merged(
            &state.named_groups_path,
            &state.home_suite_groups_path,
        )
        .await?;
        let saved = reloaded
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("reloaded group"))?;
        assert!(
            !s3::is_s3_placeholder(saved),
            "the splice restores the record"
        );
        assert!(
            saved.fork_quarantine.is_some(),
            "#1570 rc4: the quarantine survives the restart"
        );
        Ok(())
    }

    /// ADR 0109 §4 "Crash reconciliation at load", file level only (no
    /// daemon): the loader's splice replaces a placeholder by the record
    /// its binding names, keeps the stronger containment, keeps a real
    /// legacy record, and leaves a placeholder that matches neither end
    /// (or whose sidecar is damaged) in place.
    #[tokio::test]
    async fn loader_splice_follows_the_binding_and_never_loses_containment() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path();
        tokio::fs::create_dir_all(data_dir.join(s3::GROUP_RECOVERY_DIR)).await?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let mut old = GroupInfo::new(
            "splice".to_string(),
            String::new(),
            admin.agent_id(),
            "5109".repeat(16),
        );
        old.seal_commit(&admin, 1_000)?;
        let mut new = old.clone();
        new.name = "splice-new".to_string();
        new.seal_commit(&admin, 2_000)?;
        let key = old.mls_group_id.clone();
        let stable = old.stable_group_id().to_string();
        let write_sidecar_file = |binding: s3::AuthoritativeBindingV1, record: &GroupInfo| {
            let body = GroupRecoveryV1 {
                generation: 1,
                authoritative_record: serde_json::to_vec(record).ok(),
                authoritative_binding: Some(binding),
                ..GroupRecoveryV1::default()
            };
            s3::encode_sidecar(&body)
        };
        let path = data_dir
            .join(s3::GROUP_RECOVERY_DIR)
            .join(s3::sidecar_file_name(&stable));
        let binding = s3::AuthoritativeBindingV1 {
            live_key: key.clone(),
            before: s3::AuthoritativeHead::of(&old),
            before_record: Some(serde_json::to_vec(&old)?),
            after: s3::AuthoritativeHead::of(&new),
        };
        tokio::fs::write(&path, write_sidecar_file(binding.clone(), &new)?).await?;

        // After: the placeholder of `new`, with a marker installed in place
        // on disk; the splice keeps the marker.
        let mut placeholder = s3_placeholder(&new);
        placeholder.fork_quarantine = Some(x0x::groups::ForkQuarantine {
            revision: new.state_revision,
            state_hash: "sibling".to_string(),
            committed_by: hex::encode(admin.agent_id().as_bytes()),
            observed_at_ms: 1,
            snapshot: x0x::groups::ForkSnapshot {
                terminal_commit: new.terminal_commit_header(),
                conflicting_commit: new.terminal_commit_header(),
                classification: None,
            },
            no_anchor: true,
        });
        let mut merged = HashMap::from([(key.clone(), placeholder)]);
        splice_authoritative_records(data_dir, &mut merged).await;
        let spliced = merged.get(&key).ok_or_else(|| anyhow::anyhow!("spliced"))?;
        assert_eq!(spliced.name, "splice-new");
        assert!(!s3::is_s3_placeholder(spliced));
        assert!(spliced.fork_quarantine.is_some(), "containment is kept");

        // Before: the legacy write never landed.
        let mut merged = HashMap::from([(key.clone(), s3_placeholder(&old))]);
        splice_authoritative_records(data_dir, &mut merged).await;
        assert_eq!(
            merged.get(&key).map(|info| info.name.as_str()),
            Some("splice")
        );
        assert!(!merged.get(&key).is_some_and(s3::is_s3_placeholder));

        // A real legacy record is kept.
        let mut merged = HashMap::from([(key.clone(), old.clone())]);
        splice_authoritative_records(data_dir, &mut merged).await;
        assert_eq!(merged.get(&key), Some(&old));

        // Neither end: the placeholder stays, inert.
        let mut third = new.clone();
        third.seal_commit(&admin, 3_000)?;
        let mut merged = HashMap::from([(key.clone(), s3_placeholder(&third))]);
        splice_authoritative_records(data_dir, &mut merged).await;
        assert!(merged.get(&key).is_some_and(s3::is_s3_placeholder));

        // A damaged sidecar replaces nothing.
        tokio::fs::write(&path, b"X0GRCV1\0garbage").await?;
        let mut merged = HashMap::from([(key.clone(), s3_placeholder(&new))]);
        splice_authoritative_records(data_dir, &mut merged).await;
        assert!(merged.get(&key).is_some_and(s3::is_s3_placeholder));
        Ok(())
    }

    // ─── #1533 review (Codex P1, re-seat authority) ────────────────────────

    /// A contained group record on this node (the subject): `admin` created
    /// it, this node and `member` are Members, and a marker contains it.
    /// When `promoted` is given, `admin` promotes it to Admin in a signed
    /// commit that this node applies through the ordinary apply check.
    /// Durable on disk. Returns the key and the record as written.
    async fn authority_fixture(
        state: &Arc<AppState>,
        admin: &x0x::identity::AgentKeypair,
        member: &x0x::identity::AgentKeypair,
        promoted: Option<&x0x::identity::AgentKeypair>,
    ) -> anyhow::Result<(String, GroupInfo)> {
        let local = local_hex(state);
        let mut info = GroupInfo::with_policy(
            "adr0109-reseat-authority".to_string(),
            String::new(),
            admin.agent_id(),
            "1533".repeat(16),
            x0x::groups::GroupPolicy {
                discoverability: x0x::groups::GroupDiscoverability::Hidden,
                admission: x0x::groups::GroupAdmission::InviteOnly,
                confidentiality: x0x::groups::GroupConfidentiality::SignedPublic,
                ..x0x::groups::GroupPolicy::default()
            },
        );
        for peer in [
            Some(local.clone()),
            Some(hex::encode(member.agent_id().as_bytes())),
        ]
        .into_iter()
        .chain(promoted.map(|kp| Some(hex::encode(kp.agent_id().as_bytes()))))
        .flatten()
        {
            info.add_member(peer, x0x::groups::GroupRole::Member, None, None);
        }
        info.seal_commit(admin, 1_000)?;
        if let Some(promoted) = promoted {
            let promoted_hex = hex::encode(promoted.agent_id().as_bytes());
            let mut admins_copy = info.clone();
            admins_copy.set_member_role(&promoted_hex, x0x::groups::GroupRole::Admin);
            let commit = admins_copy.seal_commit(admin, 2_000)?;
            info.set_member_role(&promoted_hex, x0x::groups::GroupRole::Admin);
            info.apply_commit(
                &commit,
                x0x::groups::state_commit::ActionKind::AdminOrHigher,
            )?;
            assert_eq!(info.state_hash, admins_copy.state_hash);
        }
        info.fork_quarantine = Some(original_marker(state, &info));
        let key = info.mls_group_id.clone();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        Ok((key, info))
    }

    /// A re-seat offer signed by `signer`: an InviteV4 addressed to this
    /// node whose base roster names `signer` Admin (self-asserted), and the
    /// paired authorisation on `basis`, for a base at `base`.
    fn reseat_offer(
        info: &GroupInfo,
        signer: &x0x::identity::AgentKeypair,
        local: AgentId,
        basis: ReseatBasis,
        base: (u64, &str),
    ) -> anyhow::Result<(ReseatAuthorisation, String)> {
        let signer_hex = hex::encode(signer.agent_id().as_bytes());
        let mut invite = x0x::groups::invite::SignedInvite::new(
            info.mls_group_id.clone(),
            info.name.clone(),
            &signer.agent_id(),
            3600,
        );
        crate::server::routes::identity::populate_invite_base_state_v4(
            &mut invite,
            info,
            Some(local),
        );
        invite.base_state_revision = Some(base.0);
        invite.base_state_hash = Some(base.1.to_string());
        invite.base_roster = Some(BTreeMap::from([(
            signer_hex.clone(),
            x0x::groups::state_commit::RosterMemberSnapshot {
                role: x0x::groups::GroupRole::Admin,
                state: x0x::groups::GroupMemberState::Active,
                treekem_key_package_hash: None,
                certificate_digest: None,
            },
        )]));
        invite.sign_v4(signer, None).map_err(anyhow::Error::msg)?;
        let link = invite
            .encode_link()
            .map_err(|_| anyhow::anyhow!("invite link too large"))?;
        let authorisation = ReseatAuthorisation::sign(
            ReseatAuthorisationFields {
                group: info.stable_group_id().to_string(),
                subject: hex::encode(local.as_bytes()),
                basis,
                invite_secret_hash: s3::invite_secret_hash(&invite.invite_secret),
                invite_base_revision: base.0,
                invite_base_state_hash: base.1.to_string(),
                signer: signer_hex.clone(),
                reason_hash: s3::reason_hash("r"),
                expires_at_ms: u64::MAX / 2,
            },
            signer,
        )?;
        Ok((authorisation, link))
    }

    /// Deliver the offer through the real receive path (`handle_response`
    /// with a `Reseat` answer) and return the subject's last refusal.
    async fn deliver_offer(
        state: &Arc<AppState>,
        info: &GroupInfo,
        signer: &x0x::identity::AgentKeypair,
        offer: (ReseatAuthorisation, String),
    ) -> Option<String> {
        let response = GroupAttestResponseV1 {
            group: info.stable_group_id().to_string(),
            subject: *state.agent.agent_id().as_bytes(),
            for_head_state_hash: info.state_hash.clone(),
            answer: AttestAnswer::Reseat {
                authorisation: Box::new(offer.0),
                invite: offer.1,
            },
        };
        handle_response(state, signer.agent_id(), response).await;
        state
            .group_recovery
            .inner
            .lock()
            .await
            .subjects
            .get(info.stable_group_id())
            .and_then(|subject| subject.last_refusal.clone())
    }

    /// The live record is the original, with its marker, and no journal is
    /// open.
    async fn original_kept(state: &AppState, key: &str, info: &GroupInfo) -> anyhow::Result<()> {
        let live = state.named_groups.read().await.get(key).cloned();
        assert_eq!(
            live.map(|record| serde_json::to_value(&record))
                .transpose()?,
            Some(serde_json::to_value(info)?)
        );
        assert!(open_journal(state, info.stable_group_id()).await.is_none());
        Ok(())
    }

    /// The removal this node never saw: on the canonical chain, past its
    /// head. The invite base is that commit.
    fn unseen_removal(info: &GroupInfo) -> (ReseatBasis, u64, String) {
        let revision = info.state_revision + 1;
        let hash = "c0".repeat(32);
        (
            ReseatBasis::Removal {
                revision,
                state_hash: hash.clone(),
            },
            revision,
            hash,
        )
    }

    /// ADR 0109 row H-S3-d3: the reported `authorisation_refused` cause
    /// uses the ADR words. Each fine internal check maps to one of them.
    #[test]
    fn authorisation_refused_cause_uses_the_adr_vocabulary() {
        for (check, cause) in [
            ("signature", "signature"),
            ("signer_not_inviter", "signer"),
            ("signer_not_admin_on_base", "signer"),
            ("signer_not_admin_locally", "signer"),
            ("signer_revoked", "signer"),
            ("subject_mismatch", "subject"),
            ("basis_not_live", "basis"),
            ("basis_unknown", "basis"),
            ("base_seats_subject", "base_seats_subject"),
            ("expired", "expired"),
            ("group_mismatch", "group_mismatch"),
            ("reseat_invite_unpaired", "reseat_invite_unpaired"),
            ("record_key_divergent", "group_mismatch"),
        ] {
            assert_eq!(authorisation_refused_cause(check), cause, "{check}");
        }
    }

    /// #1533 review (Codex P1, re-seat authority): a Member signs an
    /// authorisation and an invite whose own base roster names it Admin.
    /// The subject anchors authority in its own verified roster, where the
    /// signer is a Member, so it refuses before it journals or moves
    /// anything. Before the fix the subject checked only the invite's
    /// roster and staged the forger's join. Inert (offline agent).
    #[tokio::test]
    async fn a_reseat_signed_by_a_local_non_admin_is_refused() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let forger = x0x::identity::AgentKeypair::generate()?;
        let (key, info) = authority_fixture(&state, &admin, &forger, None).await?;
        let (basis, revision, hash) = unseen_removal(&info);
        let offer = reseat_offer(
            &info,
            &forger,
            state.agent.agent_id(),
            basis,
            (revision, &hash),
        )?;
        let refusal = deliver_offer(&state, &info, &forger, offer).await;
        assert_eq!(refusal.as_deref(), Some("authorisation_refused:signer"));
        original_kept(&state, &key, &info).await
    }

    /// Control: the same offer signed by the admin of this node's own
    /// roster passes every authority check and reaches the staged join.
    /// The join cannot finish offline, so the rollback restores the
    /// original. Inert (offline agent).
    #[tokio::test]
    async fn a_reseat_signed_by_a_local_admin_reaches_the_staged_join() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let member = x0x::identity::AgentKeypair::generate()?;
        let (key, info) = authority_fixture(&state, &admin, &member, None).await?;
        let (basis, revision, hash) = unseen_removal(&info);
        let offer = reseat_offer(
            &info,
            &admin,
            state.agent.agent_id(),
            basis,
            (revision, &hash),
        )?;
        let refusal = deliver_offer(&state, &info, &admin, offer).await;
        assert!(
            refusal
                .as_deref()
                .is_some_and(|why| why.starts_with("join_")),
            "the staged join ran: {refusal:?}"
        );
        original_kept(&state, &key, &info).await
    }

    /// A Member that this node saw promoted to Admin, in a signed commit it
    /// applied, signs with the authority of its own verified roster.
    /// Inert (offline agent).
    #[tokio::test]
    async fn a_reseat_signed_by_a_locally_promoted_admin_reaches_the_staged_join(
    ) -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let member = x0x::identity::AgentKeypair::generate()?;
        let promoted = x0x::identity::AgentKeypair::generate()?;
        let (key, info) = authority_fixture(&state, &admin, &member, Some(&promoted)).await?;
        let (basis, revision, hash) = unseen_removal(&info);
        let offer = reseat_offer(
            &info,
            &promoted,
            state.agent.agent_id(),
            basis,
            (revision, &hash),
        )?;
        let refusal = deliver_offer(&state, &info, &promoted, offer).await;
        assert!(
            refusal
                .as_deref()
                .is_some_and(|why| why.starts_with("join_")),
            "the staged join ran: {refusal:?}"
        );
        original_kept(&state, &key, &info).await
    }

    /// #1689 review: [`check_reseat_keys`] needs the map key, the record's
    /// `mls_group_id` and the invite's `group_id` to be one key; any one
    /// apart is `record_key_divergent`.
    #[test]
    fn check_reseat_keys_needs_one_key() -> anyhow::Result<()> {
        let admin = x0x::identity::AgentKeypair::generate()?;
        let key = "1689".repeat(16);
        let other = "a1".repeat(32);
        let info = GroupInfo::new("keys".into(), String::new(), admin.agent_id(), key.clone());
        let invite = |group_id: &str| {
            x0x::groups::invite::SignedInvite::new(
                group_id.to_string(),
                "keys".into(),
                &admin.agent_id(),
                3600,
            )
        };
        assert_eq!(check_reseat_keys(&key, &info, &invite(&key)), Ok(()));
        for (map_key, invite_id) in [(&other, &key), (&key, &other)] {
            assert_eq!(
                check_reseat_keys(map_key, &info, &invite(invite_id)),
                Err("record_key_divergent")
            );
        }
        Ok(())
    }

    /// #1689 review (Engineer ruling, 29 Oct): a legacy record whose map
    /// key (its pre-pin genesis id) differs from its `mls_group_id` is
    /// refused with `record_key_divergent` (cause `group_mismatch`) before
    /// anything is journalled or moved. Before the guard this valid offer
    /// from a local admin reached the staged join. Inert.
    #[tokio::test]
    async fn a_reseat_of_a_record_keyed_apart_from_its_mls_group_id_is_refused(
    ) -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let member = x0x::identity::AgentKeypair::generate()?;
        let (key, mut info) = authority_fixture(&state, &admin, &member, None).await?;
        let legacy = "1689".repeat(16);
        assert_ne!(legacy, info.mls_group_id);
        info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
            legacy.clone(),
            hex::encode(admin.agent_id().as_bytes()),
            1_000,
            String::new(),
        ));
        info.fork_quarantine = Some(original_marker(&state, &info));
        {
            let mut groups = state.named_groups.write().await;
            groups.remove(&key);
            groups.insert(legacy.clone(), info.clone());
        }
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        assert_eq!(info.stable_group_id(), legacy);
        let (basis, revision, hash) = unseen_removal(&info);
        // A v4 invite signs `group_id` equal to `stable_group_id` (E1), so
        // the admin mints it at the record's stable (legacy) id.
        let mut minted_view = info.clone();
        minted_view.mls_group_id = legacy.clone();
        let offer = reseat_offer(
            &minted_view,
            &admin,
            state.agent.agent_id(),
            basis,
            (revision, &hash),
        )?;
        let refusal = deliver_offer(&state, &info, &admin, offer).await;
        assert_eq!(
            refusal.as_deref(),
            Some("authorisation_refused:group_mismatch")
        );
        for open_key in [&legacy, &info.mls_group_id] {
            assert!(state.reseat_stagings.scope_for(open_key).is_none());
        }
        original_kept(&state, &legacy, &info).await
    }

    /// A `Removal` basis is checked against this node's own chain: a
    /// commit it holds that does not remove it, or a removal after the
    /// invite base, is `basis_unknown` (reported as cause `basis`), even
    /// from a local admin. Before
    /// the fix any live `RecoveryRef` let any removal pass. Inert.
    #[tokio::test]
    async fn a_removal_basis_is_checked_against_the_local_chain() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let member = x0x::identity::AgentKeypair::generate()?;
        let (key, info) = authority_fixture(&state, &admin, &member, None).await?;
        let local = state.agent.agent_id();
        let (_, revision, hash) = unseen_removal(&info);
        let held_not_a_removal = ReseatBasis::Removal {
            revision: info.state_revision,
            state_hash: info.state_hash.clone(),
        };
        let offer = reseat_offer(&info, &admin, local, held_not_a_removal, (revision, &hash))?;
        assert_eq!(
            deliver_offer(&state, &info, &admin, offer).await.as_deref(),
            Some("authorisation_refused:basis")
        );
        original_kept(&state, &key, &info).await?;
        let after_base = ReseatBasis::Removal {
            revision: revision + 1,
            state_hash: "c1".repeat(32),
        };
        let offer = reseat_offer(&info, &admin, local, after_base, (revision, &hash))?;
        assert_eq!(
            deliver_offer(&state, &info, &admin, offer).await.as_deref(),
            Some("authorisation_refused:basis")
        );
        original_kept(&state, &key, &info).await
    }

    /// #1533 (Codex P2 @70ac6f3f), ADR 0109 §3 and §4: a manual re-seat is
    /// not Home activation, so an active admin's offer for a Home-policy
    /// group passes every check and reaches the staged join while Home
    /// activation is off. Before the fix the Home gate dropped the offer
    /// unchecked. The join cannot finish offline, so the rollback restores
    /// the original. Inert (offline agent).
    #[tokio::test]
    async fn a_home_policy_group_still_takes_a_manual_reseat() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let admin = x0x::identity::AgentKeypair::generate()?;
        let member = x0x::identity::AgentKeypair::generate()?;
        let (key, mut info) = authority_fixture(&state, &admin, &member, None).await?;
        info.home = Some(x0x::groups::HomeMetadata {
            primary_agent: hex::encode(admin.agent_id().as_bytes()),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 1,
        });
        anyhow::ensure!(is_home_policy_group(&info));
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let (basis, revision, hash) = unseen_removal(&info);
        let offer = reseat_offer(
            &info,
            &admin,
            state.agent.agent_id(),
            basis,
            (revision, &hash),
        )?;
        let refusal = deliver_offer(&state, &info, &admin, offer).await;
        assert!(
            refusal
                .as_deref()
                .is_some_and(|why| why.starts_with("join_")),
            "the staged join ran: {refusal:?}"
        );
        original_kept(&state, &key, &info).await
    }

    /// #1533 rc13 (Codex P1 @c226d28e, ZCode MAJOR 1), ADR 0109 §4 (D81):
    /// Home activation ships off, so an attestation for a Home-policy group
    /// changes nothing on disk or in memory, even when it is a valid
    /// ATA from an active admin, asked for or not. Before the fix the
    /// unsolicited ATA reached `arm_in_place`: it wrote the sidecar and
    /// placeheld the group (the §4 legacy placeholder).
    #[tokio::test]
    async fn a_home_policy_group_takes_no_attestation() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let admin = x0x::identity::AgentKeypair::generate()?;
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut info = GroupInfo::new(
            "adr0109-home".to_string(),
            String::new(),
            admin.agent_id(),
            "4110".repeat(16),
        );
        info.home = Some(x0x::groups::HomeMetadata {
            primary_agent: admin_hex.clone(),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 1,
        });
        info.add_member(
            local.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.seal_commit(&admin, 1_000)?;
        anyhow::ensure!(is_home_policy_group(&info));
        let key = info.mls_group_id.clone();
        let stable = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(key.clone(), info.clone());
        assert!(matches!(
            super::super::save_named_groups_checked(&state).await?,
            super::super::AtomicWriteOutcome::Durable
        ));
        let files = || async {
            (
                tokio::fs::read(&state.named_groups_path).await.ok(),
                tokio::fs::read(&state.home_suite_groups_path).await.ok(),
            )
        };
        let before = files().await;
        let ata = AdminTerminalAttestation::sign(
            AtaFields {
                group: stable.clone(),
                subject: local.clone(),
                attested_by: admin_hex,
                signer_public_key: hex::encode(admin.public_key().as_bytes()),
                from_revision: info.state_revision,
                from_state_hash: info.state_hash.clone(),
                sequence: vec!["a1".to_string(), "a2".to_string()],
                segment_terminal_revision: info.state_revision + 2,
                segment_terminal_epoch: None,
                issued_at_ms: now_ms(),
            },
            &admin,
        )?;
        // Unsolicited: this node asked nobody.
        let response = GroupAttestResponseV1 {
            group: stable.clone(),
            subject: *state.agent.agent_id().as_bytes(),
            for_head_state_hash: info.state_hash.clone(),
            answer: AttestAnswer::Attested(Box::new(ata.clone())),
        };
        handle_response(&state, admin.agent_id(), response).await;
        // The arming choke point refuses on its own as well.
        arm_from_response(&state, &key, &info, ata.clone()).await;
        assert!(!arm_in_place(&state, &key, &info, ata).await);
        ensure_placeholders(&state).await;

        assert!(sidecar_snapshot(&state, &stable).await.is_none());
        assert!(!is_placeheld(&state, &stable));
        assert!(open_journal(&state, &stable).await.is_none());
        assert_eq!(
            state
                .named_groups
                .read()
                .await
                .get(&key)
                .map(serde_json::to_value)
                .transpose()?,
            Some(serde_json::to_value(&info)?),
            "the live record is unchanged"
        );
        assert_eq!(files().await, before, "the Home files are unchanged");
        Ok(())
    }

    /// #1533 rc17 (ZCode MAJOR 2, ADR 0109 §11 D83): the §3 re-seat bases
    /// are bounded. Every answered request wrote an entry keyed by its
    /// requester, a banned one too, and nothing pruned the map, so fresh
    /// keys grew an admin's memory without limit. Now a banned or revoked
    /// requester stores none (the re-seat route refuses that subject), a
    /// group keeps at most `RECOVERY_LIST_CAP` subjects, and a roster
    /// subject outlives a flood of unknown requesters.
    #[tokio::test]
    async fn reseat_bases_stay_bounded_and_keep_a_roster_subject() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let keypair = state.agent.identity().agent_keypair();
        let local = local_hex(&state);
        let removed = "ab".repeat(32);
        let banned = "cd".repeat(32);
        let mut info = GroupInfo::new(
            "rc17-reseat-bases".to_string(),
            String::new(),
            state.agent.agent_id(),
            "1717".repeat(16),
        );
        for member in [&removed, &banned] {
            info.add_member(
                member.clone(),
                x0x::groups::GroupRole::Member,
                Some(local.clone()),
                None,
            );
        }
        info.seal_commit(keypair, 1_000)?;
        info.remove_member(&removed, Some(local.clone()));
        info.ban_member(&banned, Some(local.clone()));
        info.seal_commit(keypair, 2_000)?;
        let stable = info.stable_group_id().to_string();
        let key = info.mls_group_id.clone();
        state.named_groups.write().await.insert(key.clone(), info);

        let request = |requester: [u8; 32], n: u64| GroupAttestRequestV1 {
            group: stable.clone(),
            requester,
            head_revision: 1,
            head_state_hash: "00".to_string(),
            refs: vec![(
                RecoveryRef::Gap {
                    reason: "r".to_string(),
                    head_state_hash: format!("{n:064x}"),
                    terminal_revision: n,
                    terminal_state_hash: "00".to_string(),
                },
                "attestation_conflict".to_string(),
            )],
        };
        let raw = |hex_id: &str| -> anyhow::Result<[u8; 32]> {
            let bytes = hex::decode(hex_id)?;
            bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("an agent ID is 32 bytes"))
        };
        let has = |subject: &str| {
            let subject = subject.to_string();
            let stable = stable.clone();
            let state = Arc::clone(&state);
            async move {
                state
                    .group_recovery
                    .inner
                    .lock()
                    .await
                    .reseat_bases
                    .contains_key(&(stable, subject))
            }
        };

        let _ = build_answer(&state, &key, &request(raw(&removed)?, 1)).await;
        assert!(has(&removed).await, "a removed subject's basis is kept");
        let _ = build_answer(&state, &key, &request(raw(&banned)?, 2)).await;
        assert!(
            !has(&banned).await,
            "a banned requester stores no basis: the re-seat route refuses it"
        );

        let flood = 4 * s3::RECOVERY_LIST_CAP;
        for n in 0..flood {
            let mut stranger = [0u8; 32];
            stranger[..8].copy_from_slice(&(n as u64).to_be_bytes());
            stranger[31] = 0x17;
            let _ = build_answer(&state, &key, &request(stranger, 100 + n as u64)).await;
        }
        let kept = state
            .group_recovery
            .inner
            .lock()
            .await
            .reseat_bases
            .keys()
            .filter(|(group, _)| *group == stable)
            .count();
        assert!(
            kept <= s3::RECOVERY_LIST_CAP,
            "{kept} subjects kept after {flood} fresh requesters; the cap is {}",
            s3::RECOVERY_LIST_CAP
        );
        assert!(
            has(&removed).await,
            "a flood of unknown requesters does not evict a roster subject"
        );
        Ok(())
    }

    /// §3 "Beyond retention" (H-S3-r): an admin that never answered, or
    /// an admin's `not_an_admin`, does not block `readmission_required`;
    /// any other answer from a reached admin does. A member's answer
    /// (ZCode on c076826), even `base_beyond_retention`, never counts.
    #[test]
    fn readmission_counts_only_reached_admins() {
        let asked = |rows: &[(&str, &str)]| -> BTreeMap<String, String> {
            rows.iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        };
        let admins = |agent: &str| matches!(agent, "a" | "b" | "c");
        let check =
            |rows: &[(&str, &str)]| every_reached_admin_beyond_retention(&asked(rows), admins);
        let bbr = "base_beyond_retention";
        assert!(check(&[("a", bbr)]));
        assert!(check(&[
            ("a", bbr),
            ("b", "pending"),
            ("c", "not_an_admin")
        ]));
        assert!(
            check(&[("a", bbr), ("m", "attester_behind")]),
            "a member's answer never blocks"
        );
        assert!(!check(&[]));
        assert!(!check(&[("b", "pending")]));
        assert!(!check(&[("a", bbr), ("c", "attester_behind")]));
        assert!(!check(&[("m", bbr)]), "a member's refusal never decides");
        assert!(!check(&[("m", bbr), ("b", "pending")]));
    }

    /// #1699: the `GET /groups/:id` body of `key`, as the owner reads it.
    async fn get_group_json(
        state: &Arc<AppState>,
        key: &str,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let response = super::super::get_named_group(
            State(Arc::clone(state)),
            Path(key.to_string()),
            axum::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    /// #1699: an unrelated group `H`, live only, with this node Active.
    async fn unrelated_live_group(state: &AppState) -> anyhow::Result<(String, GroupInfo)> {
        let mut other = GroupInfo::new(
            "adr0109-unrelated".to_string(),
            String::new(),
            state.agent.agent_id(),
            "1699".repeat(16),
        );
        other.seal_commit(state.agent.identity().agent_keypair(), 1_500)?;
        let key = other.mls_group_id.clone();
        state
            .named_groups
            .live_write()
            .await
            .insert(key.clone(), other.clone());
        Ok((key, other))
    }

    /// #1699 (the Engineer's ruling on ADR 0109 §3 step 2): while the
    /// staged join runs, the contained original stays in the live map. A
    /// reader outside the scope (the API, the serving paths, the gates)
    /// sees the original's head, its marker and its containment, never
    /// the staged record that is sealed past it. Only the keyed swap
    /// changes the live record; it then empties the slot and closes the
    /// staging. Before #1699 the original moved out of the live map when
    /// the staging opened. Inert: an offline agent.
    #[tokio::test]
    async fn the_contained_original_keeps_its_head_marker_and_gate_until_the_keyed_swap(
    ) -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, marker, staged) = staged_reseat(&state).await?;
        let stable = info.stable_group_id().to_string();
        assert_ne!(staged.state_hash, info.state_hash);
        assert!(staged.state_revision > info.state_revision);
        // The staged join is not seated yet: its group key has not come.
        let mut unseated = staged.clone();
        unseated.name = "adr0109-staged-unseated".to_string();
        unseated.policy.confidentiality = x0x::groups::GroupConfidentiality::MlsEncrypted;
        unseated.shared_secret = None;
        state
            .named_groups
            .staging_write()
            .await
            .insert(key.clone(), unseated.clone());
        let journal = open_journal(&state, &stable)
            .await
            .expect("the journal is open");
        assert!(!journal.staged_result_ready(&unseated, &local_hex(&state), false));

        // Outside the scope: the original, with its head and marker.
        let live = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .expect("the original is live");
        assert_eq!(live.state_hash, info.state_hash);
        assert_eq!(live.state_revision, info.state_revision);
        assert_eq!(live.fork_quarantine, Some(marker.clone()));
        assert!(live.is_fork_quarantined());
        assert!(contained(&state, &live).await);
        assert!(super::super::reject_fork_quarantined(&state, &key, &live).is_some());
        assert!(
            super::super::reject_fork_quarantine_installed_before_effect(&state, &key, None)
                .await
                .is_some(),
            "the live gate holds"
        );
        // Inside the scope: the staged record.
        let in_slot = in_staging(&state, &key, async {
            state.named_groups.read().await.get(&key).cloned()
        })
        .await;
        assert_eq!(
            in_slot.map(|record| record.state_hash),
            Some(staged.state_hash.clone())
        );

        // The HTTP read path shows the original.
        let (status, body) = get_group_json(&state, &key).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], serde_json::json!(info.name), "{body}");
        assert_eq!(
            body["policy"]["confidentiality"],
            serde_json::to_value(info.policy.confidentiality)?
        );
        assert_eq!(body["fork_quarantine"], serde_json::to_value(&marker)?);
        assert!(
            open_journal(&state, &stable).await.is_some(),
            "the read did not swap"
        );
        assert_eq!(
            state
                .named_groups
                .live_read()
                .await
                .get(&key)
                .map(|record| record.state_hash.clone()),
            Some(info.state_hash.clone())
        );

        // The staged join seats: the keyed swap promotes the staged pair.
        state
            .named_groups
            .staging_write()
            .await
            .insert(key.clone(), staged.clone());
        assert!(swap_if_seated(&state, &stable).await);
        assert!(open_journal(&state, &stable).await.is_none(), "swapped");
        let live = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .expect("the staged record is live");
        assert_eq!(live.state_hash, staged.state_hash);
        assert_eq!(live.state_revision, staged.state_revision);
        assert_eq!(live.fork_quarantine, None);
        assert!(!state.named_groups.staging_read().await.contains_key(&key));
        assert!(!state.treekem_groups.staging_read().await.contains_key(&key));
        assert!(!state.mls_groups.staging_read().await.contains_key(&key));
        assert!(state.reseat_stagings.scope_for(&key).is_none());
        assert!(state.reseat_stagings.scope_for(&stable).is_none());
        Ok(())
    }

    /// #1699: a rolled-back re-seat empties the staging slot of the three
    /// group maps, closes the staging (by key and by stable id) and drops
    /// the staged join's stub from the pending join stubs. The original
    /// stays live with its head and marker. Inert: an offline agent.
    #[tokio::test]
    async fn a_rolled_back_reseat_empties_the_slot_and_keeps_the_original_live(
    ) -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, marker, _staged) = staged_reseat(&state).await?;
        let stable = info.stable_group_id().to_string();
        // The staged join's stub is under the original's key.
        state
            .pending_join_stubs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.clone());
        let digest = open_journal(&state, &stable)
            .await
            .expect("the journal is open")
            .record_digest;
        rollback_reseat(&state, &stable, digest, "issue1699_test").await;
        assert!(open_journal(&state, &stable).await.is_none(), "rolled back");
        let live = state
            .named_groups
            .read()
            .await
            .get(&key)
            .cloned()
            .expect("the original is live");
        assert_eq!(live.state_hash, info.state_hash);
        assert_eq!(live.state_revision, info.state_revision);
        assert_eq!(live.fork_quarantine, Some(marker));
        assert!(!state.named_groups.staging_read().await.contains_key(&key));
        assert!(!state.treekem_groups.staging_read().await.contains_key(&key));
        assert!(!state.mls_groups.staging_read().await.contains_key(&key));
        assert!(state.reseat_stagings.scope_for(&key).is_none());
        assert!(state.reseat_stagings.scope_for(&stable).is_none());
        assert!(!state
            .pending_join_stubs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&key));
        assert!(on_disk_keys(&state).await?.contains(&key));
        Ok(())
    }

    /// #1699: a roster refresh that a step of the staged join runs (inside
    /// the scope) publishes every group's roster: the unrelated group `H`
    /// from the live map and the group under re-seat with its STAGED
    /// members. Before the fix the refresh read the map that the scope
    /// selects, the staging slot only, and dropped every other group's
    /// gossip roster. Inert: an offline agent.
    #[tokio::test]
    async fn a_roster_refresh_inside_the_scope_keeps_every_other_groups_roster(
    ) -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _marker, mut staged) = staged_reseat(&state).await?;
        let g_stable = info.stable_group_id().to_string();
        // The staged record has a member that the original does not.
        let newcomer = x0x::identity::AgentKeypair::generate()?.agent_id();
        staged.add_member(
            hex::encode(newcomer.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(local_hex(&state)),
            None,
        );
        staged.seal_commit(state.agent.identity().agent_keypair(), 3_000)?;
        state
            .named_groups
            .staging_write()
            .await
            .insert(key.clone(), staged.clone());
        assert!(!info
            .active_members()
            .any(|member| member.agent_id == hex::encode(newcomer.as_bytes())));
        let (_h_key, other) = unrelated_live_group(&state).await?;
        let h_stable = other.stable_group_id().to_string();

        in_staging(
            &state,
            &key,
            super::super::refresh_group_rosters_for_gossip(&state),
        )
        .await;

        let published = state.group_roster_gossip_lock.lock().await.clone();
        let agents_of = |stable: &str| {
            published
                .get(stable)
                .cloned()
                .flatten()
                .map(|(published_stable, topic, agents)| {
                    let mut agents: Vec<_> =
                        agents.iter().map(|a| hex::encode(a.as_bytes())).collect();
                    agents.sort();
                    (published_stable, topic, agents)
                })
        };
        let sorted = |record: &GroupInfo| {
            let mut agents: Vec<_> = record
                .active_members()
                .map(|member| member.agent_id.clone())
                .collect();
            agents.sort();
            agents
        };
        assert_eq!(
            agents_of(&h_stable),
            Some((
                h_stable.clone(),
                other.metadata_topic.clone(),
                sorted(&other)
            )),
            "H's live roster is published: {published:?}"
        );
        assert_eq!(
            agents_of(&g_stable),
            Some((
                g_stable.clone(),
                staged.metadata_topic.clone(),
                sorted(&staged)
            )),
            "G's staged roster is published: {published:?}"
        );
        assert_ne!(sorted(&staged), sorted(&info));
        Ok(())
    }

    /// #1699: inside an open re-seat scope, a whole-node worker spawned
    /// through `outside_reseat_scope` sees the live map (the unrelated
    /// group `H` and the contained original of `G`), and a plain
    /// `spawn_detached` task inherits the scope and sees the staging slot
    /// (the staged record of `G`, no `H`). Before the fix a spawned task
    /// lost the scope, so a step that the staged join spawned wrote the
    /// live map. Inert: an offline agent.
    #[tokio::test]
    async fn a_whole_node_worker_started_in_the_scope_sees_the_live_map() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let (key, info, _marker, staged) = staged_reseat(&state).await?;
        let (h_key, _other) = unrelated_live_group(&state).await?;
        type Seen = (bool, Option<String>);
        let probe = |state: Arc<AppState>,
                     key: String,
                     h_key: String,
                     tx: tokio::sync::oneshot::Sender<Seen>| async move {
            let groups = state.named_groups.read().await;
            let seen = (
                groups.contains_key(&h_key),
                groups.get(&key).map(|record| record.state_hash.clone()),
            );
            drop(groups);
            let _ = tx.send(seen);
        };
        let (worker_tx, worker_rx) = tokio::sync::oneshot::channel();
        let (step_tx, step_rx) = tokio::sync::oneshot::channel();
        in_staging(&state, &key, async {
            assert!(
                state.spawn_detached(crate::server::reseat_scope::outside_reseat_scope(probe(
                    Arc::clone(&state),
                    key.clone(),
                    h_key.clone(),
                    worker_tx,
                )))
            );
            assert!(state.spawn_detached(probe(
                Arc::clone(&state),
                key.clone(),
                h_key.clone(),
                step_tx,
            )));
        })
        .await;
        let worker = tokio::time::timeout(Duration::from_secs(10), worker_rx).await??;
        let step = tokio::time::timeout(Duration::from_secs(10), step_rx).await??;
        assert_eq!(
            worker,
            (true, Some(info.state_hash.clone())),
            "the whole-node worker sees the live map"
        );
        assert_eq!(
            step,
            (false, Some(staged.state_hash.clone())),
            "a step that the staged join spawns stays in the staging slot"
        );
        Ok(())
    }

    /// #1699 (#1689 row c): outside the scope of an open re-seat staging,
    /// the contained original's membership label ignores the staged join's
    /// attempt, which shares its key; inside the scope the attempt counts.
    /// Inert (offline agent).
    #[tokio::test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the test pins the seat label itself, not a route's admission"
    )]
    async fn the_originals_membership_label_ignores_the_staged_joins_attempt() -> anyhow::Result<()>
    {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let local = local_hex(&state);
        let key = "e7".repeat(16);
        let record = GroupInfo::new(
            "contained".to_string(),
            String::new(),
            AgentId([7; 32]),
            key.clone(),
        );
        let stable = record.stable_group_id().to_string();
        super::super::record_expected_join_result_inviter(
            &state,
            super::super::join_result_key(&stable, &local),
            "ab".repeat(32),
        );
        let label = || super::super::local_join_membership_state(&state, &record, &local);
        assert_eq!(
            label().await,
            "pending_authority_commit",
            "no staging: the attempt counts"
        );
        let scope = state.reseat_stagings.open(&key, &stable);
        assert_eq!(
            label().await,
            "not_member",
            "the live original keeps its label"
        );
        let inside = crate::server::reseat_scope::in_reseat_scope(scope, label()).await;
        assert_eq!(
            inside, "pending_authority_commit",
            "the staged join sees its attempt"
        );
        assert!(state.reseat_stagings.close(&key));
        assert_eq!(
            label().await,
            "pending_authority_commit",
            "closed: as before"
        );
        Ok(())
    }
}
