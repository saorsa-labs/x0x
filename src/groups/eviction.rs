//! ADR 0110 (slice S4 of ADR 0088): revocation eviction, designated first.
//!
//! This module holds the pure, I/O-free core of S4:
//!
//! - [`S4Timing`]: the measured timing values (W, completion bound, Δ and
//!   the restart sync wait), from the `s4_timing_measurement` p99.9
//!   numbers recorded in the #1357 PR body (D69, D73).
//! - The obligation model (§1): one row per (stable group ID, target agent
//!   ID), with the set of verified trigger hashes, the phase (§5) and the
//!   typed waiting cause (D64).
//! - [`RevocationIntake`]: the queue that the single post-verification hook
//!   in `lib.rs` feeds after `verify_and_insert` returns `Ok(true)`.
//!
//! The daemon side (`x0xd`) owns scheduling, locks, persistence I/O and the
//! commit path. This module never touches the network or the disk.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::EXPIRY_CLOCK_SKEW_SECS;

/// Expiry tolerance τ (D127): today's [`EXPIRY_CLOCK_SKEW_SECS`], so the
/// eviction trigger and the D60 delivery refusal use one test.
pub const EXPIRY_TOLERANCE_SECS: u64 = EXPIRY_CLOCK_SKEW_SECS;

/// Completed rows drop their signed evidence bodies this long after
/// verified completion (D128).
pub const COMPLETED_EVIDENCE_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// At most this many compact completed records are kept per group, oldest
/// first out (D128).
pub const MAX_COMPACT_RECORDS_PER_GROUP: usize = 4096;

/// At most this many completed rows per group keep their crypto-only
/// exclusion frame (`outgoing_event`) as replay evidence for ADR 0110 §4
/// catch-up after a restart, newest first. Older rows drop the frame.
pub const MAX_REPLAY_FRAMES_PER_GROUP: usize = 16;

/// Whether `bytes` is a crypto-only exclusion frame (`X0XCE1`): the one
/// saved event a completed row keeps as replay evidence.
fn is_replay_frame(bytes: &[u8]) -> bool {
    bytes.starts_with(crate::groups::crypto_exclusion::CRYPTO_EXCLUSION_PREFIX)
}

// ─── Timing (D69, D73) ─────────────────────────────────────────────────────

/// The S4 timing values. Every S4 budget reads them from here.
///
/// ADR 0110 §2: W and the completion bound come from the W3-H p99.9 of
/// hand-off delivery-and-verification skew, plus fsync, CPU-stall and
/// seal-and-propagation time, with margin. Δ is at least the measured
/// p99.9 seal-and-head-propagation time. The restart sync wait is at least
/// the measured p99.9 head catch-up.
///
/// The defaults are the `s4_timing_measurement` values (ADR 0110 option B,
/// David 20 Oct 2026): 1.5 × the p99.9 sums of the contended loopback
/// measurement plus a derived 375 ms RTT WAN term, rounded up to 1 s. The
/// #1357 PR body records the samples and the arithmetic. They are not the
/// 2 s / 5 s values that D69 rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S4Timing {
    /// W: only the designated admin may start an exclusion before this
    /// much suspend-inclusive monotonic time has passed since T_obs.
    pub designated_window: Duration,
    /// The completion bound: the time from T_obs to a verified exclusion
    /// while one eligible compatible admin and the evidence are reachable.
    pub completion_bound: Duration,
    /// Δ: the stagger between fallback ranks. Rank r may start at
    /// `T_obs + W + (r − 1)·Δ`.
    pub fallback_stagger: Duration,
    /// The bounded wait for a head catch-up round after a restart.
    pub restart_sync_wait: Duration,
}

impl S4Timing {
    /// W: 1.5 × (hand-off p99.9 + fsync p99.9 + seal-and-propagation),
    /// 17.4 s, rounded up.
    pub const DESIGNATED_WINDOW: Duration = Duration::from_secs(18);
    /// The completion bound while the designated admin is reachable: the
    /// same inputs as W.
    pub const COMPLETION_BOUND: Duration = Duration::from_secs(18);
    /// Δ: 1.5 × the seal-and-head-propagation p99.9, 10.8 s, rounded up.
    pub const FALLBACK_STAGGER: Duration = Duration::from_secs(11);
    /// The restart sync wait: 1.5 × the restart head catch-up p99.9,
    /// 12.3 s, rounded up (inside D73's provisional 10 s to 30 s range).
    pub const RESTART_SYNC_WAIT: Duration = Duration::from_secs(13);

    /// The earliest elapsed time since T_obs at which fallback rank `rank`
    /// may start. Rank 0 is the designated admin and may start at once.
    #[must_use]
    pub fn fallback_offset(&self, rank: usize) -> Duration {
        if rank == 0 {
            return Duration::ZERO;
        }
        let extra = u32::try_from(rank.saturating_sub(1)).unwrap_or(u32::MAX);
        self.designated_window
            .saturating_add(self.fallback_stagger.saturating_mul(extra))
    }
}

impl Default for S4Timing {
    fn default() -> Self {
        Self {
            designated_window: Self::DESIGNATED_WINDOW,
            completion_bound: Self::COMPLETION_BOUND,
            fallback_stagger: Self::FALLBACK_STAGGER,
            restart_sync_wait: Self::RESTART_SYNC_WAIT,
        }
    }
}

// ─── Typed states (D64) ────────────────────────────────────────────────────

/// A typed, visible wait that names its cause (D64, L3). The `snake_case`
/// names are the public status strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WaitingCause {
    /// The obligation or its evidence is not durable yet; retrying.
    WaitingForDurableIntake,
    /// A lower-ranked admin is designated; this node waits for its fallback
    /// time.
    WaitingForDesignatedAdmin,
    /// The hand-off has not reached the designated admin and returned no
    /// definitive failure; priority is kept through W only.
    UnresolvedDesignatedAdmin,
    /// A catch-up round must complete before any S4 seal.
    WaitingForHeadSync,
    /// The target's KeyPackage is needed for the TreeKEM removal.
    WaitingForMemberKeyPackage,
    /// A competing exclusion landed on another branch.
    WaitingForForkResolution,
    /// A receiver lacks a capability that the commit needs.
    WaitingForReceiverUpgrade,
    /// This node may not seal (demoted, removed, revoked, left, or its own
    /// selected certificate expired).
    LocalCommitterIneligible,
    /// Verified revocations cover every Admin-or-higher Active seat.
    WaitingForEligibleAdminRevocation,
    /// The roster has no Active admin at all (ADR 0088 §2 item 3).
    WaitingForActiveAdmin,
    /// Every admin other than the target holds an expired selected
    /// certificate.
    WaitingForAdminCertificateRenewal,
    /// The committed certificate bytes for a digest-only seat are missing.
    WaitingForCertificateEvidence,
    /// ADR 0094 trial: S4 writes wait for the host commit.
    WaitingForHostCommit,
    /// The S4 sidecar is being rebuilt by ADR 0108 §5a.
    RebuildingObligationStore,
    /// The expiry clock check has not passed the raw `not_after` yet.
    WaitingForCertificateExpiry,
}

impl WaitingCause {
    /// The public status string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WaitingForDurableIntake => "waiting_for_durable_intake",
            Self::WaitingForDesignatedAdmin => "waiting_for_designated_admin",
            Self::UnresolvedDesignatedAdmin => "unresolved_designated_admin",
            Self::WaitingForHeadSync => "waiting_for_head_sync",
            Self::WaitingForMemberKeyPackage => "waiting_for_member_key_package",
            Self::WaitingForForkResolution => "waiting_for_fork_resolution",
            Self::WaitingForReceiverUpgrade => "waiting_for_receiver_upgrade",
            Self::LocalCommitterIneligible => "local_committer_ineligible",
            Self::WaitingForEligibleAdminRevocation => "waiting_for_eligible_admin_revocation",
            Self::WaitingForActiveAdmin => "waiting_for_active_admin",
            Self::WaitingForAdminCertificateRenewal => "waiting_for_admin_certificate_renewal",
            Self::WaitingForCertificateEvidence => "waiting_for_certificate_evidence",
            Self::WaitingForHostCommit => "waiting_for_host_commit",
            Self::RebuildingObligationStore => "rebuilding_obligation_store",
            Self::WaitingForCertificateExpiry => "waiting_for_certificate_expiry",
        }
    }
}

/// Why a designated admin is waiting, for `waiting_for_designated_admin`
/// and `unresolved_designated_admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DesignatedWaitDetail {
    /// The designated admin is compatible; this node waits for its rank.
    Rank,
    /// The designated admin lacks `eviction_handoff_v1` (§4).
    DesignatedAdminUnsupported,
}

/// The outcome of this node's outbound hand-off dispatch attempt against
/// one designated admin (§2, L170–L173), recorded when the attempt
/// completes, so an attempt still in flight keeps the plain designated
/// wait. Only `Unresolved` and `Unsupported` persist (§5 v3): a routine
/// `ExchangeReached` is memory state of its attempt, so a store without
/// an outcome-bearing record stays v1/v2 (Engineer ruling, 4 Nov 2026
/// 08:25 GMT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DesignatedHandoffOutcome {
    /// The hand-off reached an authenticated direct or routed exchange
    /// with the designated admin (L170: `send_direct` succeeded).
    /// Routine, so it never rides the stored file; a completion drops
    /// the record entirely.
    ExchangeReached,
    /// The attempt completed without such an exchange and without a
    /// definitive current routing or eligibility failure: the designated
    /// route is unresolved (L171). There is no dispatch retry, and a
    /// later receipt does not rewrite the record. The pass drops it at
    /// W and when the designation changes (the record names another
    /// admin), and the row drops it when it completes, terminates or
    /// reopens (Engineer ruling, 4 Nov 2026 17:22 GMT).
    Unresolved,
    /// The designated admin's current verified advert lacks
    /// `eviction_handoff_v1` (§4, L173), or its transport refused the
    /// send for that lack (`RecipientUpgradeRequired`): a definitive
    /// eligibility failure.
    Unsupported,
    /// A definitive policy refusal (L171): the designated admin's own
    /// acknowledgement that its trust policy refused this sender
    /// (`RecipientRejected`), or this node's ADR-0043 pairing policy
    /// refused the designated admin's machine. Not an unresolved route
    /// and not a §4 capability lack, so the row keeps the plain
    /// designated wait. Never stored (Engineer ruling, 4 Nov 2026
    /// 18:15 GMT).
    PolicyRefused,
}

impl DesignatedHandoffOutcome {
    /// Whether the outcome rides the `.evs` v3 extension (§5). Only
    /// `Unresolved` and `Unsupported` do; a routine `ExchangeReached`
    /// and a `PolicyRefused` stay in memory (Engineer rulings, 4 Nov
    /// 2026 08:25 and 18:15 GMT).
    #[must_use]
    pub(crate) fn persists(self) -> bool {
        matches!(self, Self::Unresolved | Self::Unsupported)
    }
}

/// This node's recorded outbound hand-off dispatch against one
/// designated admin. The record names the admin it targeted, so a
/// designation change voids it; the S4 pass then drops it, and it also
/// drops it at W. The dispatch itself runs once per
/// attempt — when the row first dispatches, and again after a reopen —
/// so a designation change alone sends no new attempt and the new
/// designated admin holds no record until the row reopens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignatedHandoffRecord {
    /// The designated admin the attempt targeted.
    pub designated: [u8; 32],
    /// The outcome of the completed attempt.
    pub outcome: DesignatedHandoffOutcome,
}

/// The persisted phase of one obligation (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Phase {
    /// Work is known and not started, or was abandoned back to pending.
    Pending,
    /// A `.evjournal` holds a prepared transition; no legacy commit yet.
    Prepared,
    /// The exclusion is committed locally; delivery is not finished.
    CommittedDeliveryPending,
    /// A verified exclusion is on the current chain.
    Complete,
    /// The work ended without a removal.
    Terminated,
}

impl Phase {
    /// The public status string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Prepared => "prepared",
            Self::CommittedDeliveryPending => "committed_delivery_pending",
            Self::Complete => "complete",
            Self::Terminated => "terminated",
        }
    }

    /// Whether S4 still owes work for this row.
    #[must_use]
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Prepared | Self::CommittedDeliveryPending
        )
    }
}

/// The cause recorded with [`Phase::Terminated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TerminationCause {
    /// A signed group deletion ended the work (ADR 0088 §2 item 5).
    GroupDeleted,
    /// A verified `certificate_rebind_v1` renewed the seat (§4a).
    CertificateValid,
    /// #1023 (Engineer ruling 1 Nov 2026 02:36 GMT): the creator seat
    /// never becomes eviction-eligible from its own expired certificate
    /// alone. An expiry row persisted by an earlier build that names the
    /// creator ends with this cause; no new creator row can open.
    CreatorSeatExempt,
}

impl TerminationCause {
    /// The public status string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GroupDeleted => "group_deleted",
            Self::CertificateValid => "certificate_valid",
            Self::CreatorSeatExempt => "creator_seat_exempt",
        }
    }
}

// ─── Obligation key, triggers and rows (§1) ────────────────────────────────

/// The obligation key: (stable group ID, target agent ID).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvictionKey {
    /// The group's stable ID (`GroupInfo::stable_group_id`).
    pub stable_group_id: String,
    /// The target agent ID (raw 32 bytes).
    pub target: [u8; 32],
}

impl EvictionKey {
    /// Build a key.
    #[must_use]
    pub fn new(stable_group_id: impl Into<String>, target: [u8; 32]) -> Self {
        Self {
            stable_group_id: stable_group_id.into(),
            target,
        }
    }
}

/// One verified trigger (§1, §1a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionTrigger {
    /// A verified Agent-subject revocation of the target.
    AgentRevocation {
        /// `RevocationRecord::record_hash`.
        record_hash: [u8; 32],
        /// The signed record (bincode, as the revocation store holds it).
        /// Persisted as evidence; may be empty when the store keeps it.
        record_bytes: Vec<u8>,
    },
    /// A verified, chained self-leave of the target.
    SelfLeave {
        /// The head hash at which the leave was observed on the verified
        /// chain.
        commit_hash: String,
    },
    /// The committed certificate of an Active seat in an `OwnerCertified`
    /// group expired on this node's clock (§1a).
    CertificateExpiry {
        /// `owner_cert::certificate_digest_hex` of the committed certificate.
        certificate_digest: String,
        /// Its signed `not_after` (Unix seconds).
        not_after: u64,
    },
}

/// The result of one intake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeOutcome {
    /// A new obligation row was created; T_obs starts now.
    Created,
    /// The row existed; the trigger added evidence. No window is extended.
    AddedEvidence,
    /// The trigger was already recorded. Nothing changed.
    Duplicate,
    /// A completed or terminated row was reopened for a new incarnation
    /// or for a revocation after a renewal.
    Reopened,
}

impl IntakeOutcome {
    /// Whether the store changed and must be persisted.
    #[must_use]
    pub fn changed(self) -> bool {
        !matches!(self, Self::Duplicate)
    }
}

/// The typed waiting state shown on a row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitingState {
    /// The cause.
    pub cause: WaitingCause,
    /// The agent IDs the state names (designated admin, revoked admins,
    /// holding survivors).
    pub named: Vec<[u8; 32]>,
    /// For the designated-wait causes (`waiting_for_designated_admin`,
    /// `unresolved_designated_admin`): why.
    pub designated_detail: Option<DesignatedWaitDetail>,
    /// For timed waits: the remaining budget in milliseconds at the time
    /// the state was computed.
    pub remaining_ms: Option<u64>,
}

impl WaitingState {
    /// A state with only a cause.
    #[must_use]
    pub fn cause(cause: WaitingCause) -> Self {
        Self {
            cause,
            named: Vec::new(),
            designated_detail: None,
            remaining_ms: None,
        }
    }
}

/// One obligation row. This is the frozen v1 persisted shape (§5): field
/// order is the postcard layout; append only under a new header version.
/// A `#[serde(skip)]` field stays out of that layout and persists in a
/// versioned extension instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationRow {
    /// Stable group ID.
    pub stable_group_id: String,
    /// Target agent ID.
    pub target: [u8; 32],
    /// Verified revocation record hashes.
    pub revocation_hashes: BTreeSet<[u8; 32]>,
    /// Signed revocation records (bincode), keyed by hash. Dropped 30 days
    /// after verified completion (D128).
    pub revocation_records: BTreeMap<[u8; 32], Vec<u8>>,
    /// Verified self-leave commit hashes.
    pub self_leave_commits: BTreeSet<String>,
    /// Expired committed certificates: digest → `not_after`.
    pub expired_certificates: BTreeMap<String, u64>,
    /// The target's TreeKEM KeyPackage hash when the row opened (seat/leaf
    /// incarnation). An old exclusion never certifies a new leaf.
    pub incarnation: Option<String>,
    /// Wall-clock time of first observation (display only, Unix ms).
    pub observed_at_unix_ms: u64,
    /// Wall-clock time of the first hand-off dispatch attempt (Unix ms).
    pub first_dispatch_unix_ms: Option<u64>,
    /// Wall-clock time of the earliest verified hand-off receipt (Unix ms).
    pub earliest_handoff_receipt_unix_ms: Option<u64>,
    /// Boot identity that recorded `elapsed_budget_ms`.
    pub boot_id: [u8; 16],
    /// Monotonic budget consumed since T_obs at the last persist (ms).
    pub elapsed_budget_ms: u64,
    /// The designated admin at the last derivation.
    pub designated: Option<[u8; 32]>,
    /// Fallback ranks (rank 1 first) at the last derivation.
    pub ranks: Vec<[u8; 32]>,
    /// Phase.
    pub phase: Phase,
    /// Cause for [`Phase::Terminated`].
    pub termination: Option<TerminationCause>,
    /// The typed waiting state at the last evaluation.
    pub waiting: Option<WaitingState>,
    /// The parent head the prepared transition extends.
    pub parent_head: Option<String>,
    /// The head of the verified exclusion.
    pub result_head: Option<String>,
    /// The epoch after the verified exclusion.
    pub result_epoch: Option<u64>,
    /// The exact outgoing event of a prepared or committed transition.
    pub outgoing_event: Option<Vec<u8>>,
    /// Wall-clock time of verified completion (Unix ms).
    pub completed_at_unix_ms: Option<u64>,
    /// This node's recorded outbound hand-off dispatch outcome against
    /// the row's designated admin (§2, L170–L173). `#[serde(skip)]`: the
    /// v1 body above is frozen (§5), so the record persists only in the
    /// `.evs` v3 extension ([`EVS_HEADER_V3`]) and an old-header row
    /// loads with the `None` default. Only `unresolved` and
    /// `unsupported` outcomes ride that extension; a routine
    /// `exchange_reached` stays in memory. The record is dropped at W,
    /// on a designation change, and when the row completes, terminates
    /// or reopens (Engineer rulings, 4 Nov 2026 08:25 and 17:22 GMT).
    #[serde(skip)]
    pub designated_handoff: Option<DesignatedHandoffRecord>,
}

impl ObligationRow {
    fn new(key: &EvictionKey, now_unix_ms: u64, boot_id: [u8; 16]) -> Self {
        Self {
            stable_group_id: key.stable_group_id.clone(),
            target: key.target,
            revocation_hashes: BTreeSet::new(),
            revocation_records: BTreeMap::new(),
            self_leave_commits: BTreeSet::new(),
            expired_certificates: BTreeMap::new(),
            incarnation: None,
            observed_at_unix_ms: now_unix_ms,
            first_dispatch_unix_ms: None,
            earliest_handoff_receipt_unix_ms: None,
            boot_id,
            elapsed_budget_ms: 0,
            designated: None,
            ranks: Vec::new(),
            phase: Phase::Pending,
            termination: None,
            waiting: None,
            parent_head: None,
            result_head: None,
            result_epoch: None,
            outgoing_event: None,
            completed_at_unix_ms: None,
            designated_handoff: None,
        }
    }

    /// The obligation key.
    #[must_use]
    pub fn key(&self) -> EvictionKey {
        EvictionKey::new(self.stable_group_id.clone(), self.target)
    }

    /// Whether any revocation evidence is held. A renewal never cancels it.
    #[must_use]
    pub fn has_revocation(&self) -> bool {
        !self.revocation_hashes.is_empty()
    }

    /// Whether the only triggers are certificate expiry.
    #[must_use]
    pub fn expiry_only(&self) -> bool {
        self.revocation_hashes.is_empty()
            && self.self_leave_commits.is_empty()
            && !self.expired_certificates.is_empty()
    }

    /// The trigger kinds, for status output.
    #[must_use]
    pub fn trigger_kinds(&self) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        if !self.revocation_hashes.is_empty() {
            kinds.push("agent_revocation");
        }
        if !self.self_leave_commits.is_empty() {
            kinds.push("self_leave");
        }
        if !self.expired_certificates.is_empty() {
            kinds.push("certificate_expiry");
        }
        kinds
    }

    /// Record one trigger. Returns whether the row changed.
    fn absorb(&mut self, trigger: EvictionTrigger) -> bool {
        match trigger {
            EvictionTrigger::AgentRevocation {
                record_hash,
                record_bytes,
            } => {
                let added = self.revocation_hashes.insert(record_hash);
                if added && !record_bytes.is_empty() {
                    self.revocation_records.insert(record_hash, record_bytes);
                }
                added
            }
            EvictionTrigger::SelfLeave { commit_hash } => {
                // One leave proof per incarnation is enough: a later
                // observation of the same leave at a newer head is not a
                // new trigger.
                if self.self_leave_commits.is_empty() {
                    self.self_leave_commits.insert(commit_hash)
                } else {
                    false
                }
            }
            EvictionTrigger::CertificateExpiry {
                certificate_digest,
                not_after,
            } => self
                .expired_certificates
                .insert(certificate_digest, not_after)
                .is_none(),
        }
    }

    fn reopen(&mut self, now_unix_ms: u64, boot_id: [u8; 16]) {
        self.phase = Phase::Pending;
        self.termination = None;
        self.waiting = None;
        self.parent_head = None;
        self.result_head = None;
        self.result_epoch = None;
        self.outgoing_event = None;
        self.completed_at_unix_ms = None;
        self.observed_at_unix_ms = now_unix_ms;
        self.first_dispatch_unix_ms = None;
        self.earliest_handoff_receipt_unix_ms = None;
        // The record belongs to the superseded attempt; the fresh
        // attempt starts with none (#1581 review r7).
        self.designated_handoff = None;
        self.boot_id = boot_id;
        self.elapsed_budget_ms = 0;
    }

    /// Drop the hand-off record once it no longer applies, so a stored
    /// `unresolved` or `unsupported` outcome leaves the `.evs` v3
    /// extension and the file returns to v1/v2 (Engineer ruling, 4 Nov
    /// 2026 17:22 GMT). The record ends at W (`past_window`): L171 keeps
    /// an unresolved route's priority "through W, not forever", and the
    /// §4 unsupported wait also lasts for W. It also ends when the
    /// current designated admin (`designated`, `None` when no
    /// designation is known this pass) is not the admin the record
    /// names: the attempt targeted an admin that is no longer
    /// designated. Returns whether the stored file changes, that is
    /// whether the dropped record was an outcome-bearing one.
    pub(crate) fn retire_designated_handoff(
        &mut self,
        designated: Option<[u8; 32]>,
        past_window: bool,
    ) -> bool {
        let Some(record) = self.designated_handoff else {
            return false;
        };
        let redesignated = designated.is_some_and(|current| current != record.designated);
        if !(past_window || redesignated) {
            return false;
        }
        self.designated_handoff = None;
        record.outcome.persists()
    }
}

/// All S4 obligations held by this node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObligationStore {
    rows: BTreeMap<EvictionKey, ObligationRow>,
}

impl ObligationStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store from decoded rows. Later duplicates of a key are
    /// merged into the first row.
    #[must_use]
    pub fn from_rows(rows: Vec<ObligationRow>) -> Self {
        let mut store = Self::new();
        for row in rows {
            let key = row.key();
            match store.rows.get_mut(&key) {
                Some(existing) => {
                    existing.revocation_hashes.extend(row.revocation_hashes);
                    existing.revocation_records.extend(row.revocation_records);
                    existing.self_leave_commits.extend(row.self_leave_commits);
                    existing
                        .expired_certificates
                        .extend(row.expired_certificates);
                }
                None => {
                    store.rows.insert(key, row);
                }
            }
        }
        store
    }

    /// The rows in key order.
    pub fn rows(&self) -> impl Iterator<Item = &ObligationRow> {
        self.rows.values()
    }

    /// The rows as an owned list (for encoding).
    #[must_use]
    pub fn to_rows(&self) -> Vec<ObligationRow> {
        self.rows.values().cloned().collect()
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// One row.
    #[must_use]
    pub fn get(&self, key: &EvictionKey) -> Option<&ObligationRow> {
        self.rows.get(key)
    }

    /// One row, mutable.
    pub fn get_mut(&mut self, key: &EvictionKey) -> Option<&mut ObligationRow> {
        self.rows.get_mut(key)
    }

    /// Open rows of one group.
    pub fn open_rows_for_group<'a>(
        &'a self,
        stable_group_id: &'a str,
    ) -> impl Iterator<Item = &'a ObligationRow> + 'a {
        self.rows
            .values()
            .filter(move |row| row.stable_group_id == stable_group_id && row.phase.is_open())
    }

    /// All rows of one group, open or not.
    pub fn rows_for_group<'a>(
        &'a self,
        stable_group_id: &'a str,
    ) -> impl Iterator<Item = &'a ObligationRow> + 'a {
        self.rows
            .values()
            .filter(move |row| row.stable_group_id == stable_group_id)
    }

    /// §1 intake. Duplicates and extra hashes for the same excluded leaf do
    /// not create another worker, extend a window or undo a completion.
    ///
    /// `incarnation` is the target's current seat/leaf identity
    /// ([`crate::groups::crypto_exclusion::seat_incarnation`]). A completed
    /// row reopens when any trigger (revocation, self-leave or certificate
    /// expiry) names a different known incarnation: a rejoin followed by a
    /// later departure is new work. A trigger of the row's own incarnation,
    /// such as a replay of the old departure, never reopens it (#1508
    /// review, Codex P1). A terminated row reopens only when a revocation
    /// arrives after a renewal terminated expiry work.
    pub fn intake(
        &mut self,
        key: &EvictionKey,
        trigger: EvictionTrigger,
        incarnation: Option<&str>,
        now_unix_ms: u64,
        boot_id: [u8; 16],
    ) -> IntakeOutcome {
        let is_revocation = matches!(trigger, EvictionTrigger::AgentRevocation { .. });
        let is_self_leave = matches!(trigger, EvictionTrigger::SelfLeave { .. });
        let Some(row) = self.rows.get_mut(key) else {
            let mut row = ObligationRow::new(key, now_unix_ms, boot_id);
            row.incarnation = incarnation.map(str::to_string);
            row.absorb(trigger);
            self.rows.insert(key.clone(), row);
            return IntakeOutcome::Created;
        };
        match row.phase {
            Phase::Complete => {
                let new_incarnation = match (row.incarnation.as_deref(), incarnation) {
                    (Some(old), Some(new)) => old != new,
                    _ => false,
                };
                if new_incarnation {
                    // One leave proof per incarnation: the new departure
                    // replaces the old seat's proof.
                    if is_self_leave {
                        row.self_leave_commits.clear();
                    }
                    row.absorb(trigger);
                    row.incarnation = incarnation.map(str::to_string);
                    row.reopen(now_unix_ms, boot_id);
                    return IntakeOutcome::Reopened;
                }
                if row.absorb(trigger) {
                    IntakeOutcome::AddedEvidence
                } else {
                    IntakeOutcome::Duplicate
                }
            }
            Phase::Terminated => {
                let renewed = row.termination == Some(TerminationCause::CertificateValid);
                if renewed && is_revocation {
                    // A renewal never cancels revocation work (§1a).
                    row.absorb(trigger);
                    row.reopen(now_unix_ms, boot_id);
                    return IntakeOutcome::Reopened;
                }
                IntakeOutcome::Duplicate
            }
            Phase::Pending | Phase::Prepared | Phase::CommittedDeliveryPending => {
                if row.absorb(trigger) {
                    IntakeOutcome::AddedEvidence
                } else {
                    IntakeOutcome::Duplicate
                }
            }
        }
    }

    /// Reopen a completed row whose completion proof is gone: this node's
    /// tree holds the target's leaf again (#1508 rc15). Returns whether the
    /// row changed.
    pub fn reopen_complete(
        &mut self,
        key: &EvictionKey,
        now_unix_ms: u64,
        boot_id: [u8; 16],
    ) -> bool {
        match self.rows.get_mut(key) {
            Some(row) if row.phase == Phase::Complete => {
                row.reopen(now_unix_ms, boot_id);
                true
            }
            _ => false,
        }
    }

    /// Mark a row complete with the verified exclusion's head and epoch.
    /// Returns whether the row changed.
    pub fn complete(
        &mut self,
        key: &EvictionKey,
        result_head: Option<String>,
        result_epoch: Option<u64>,
        now_unix_ms: u64,
    ) -> bool {
        let Some(row) = self.rows.get_mut(key) else {
            return false;
        };
        if !row.phase.is_open() {
            return false;
        }
        row.phase = Phase::Complete;
        row.waiting = None;
        row.result_head = result_head;
        row.result_epoch = result_epoch;
        // The work is over, so the attempt's outcome no longer applies
        // (Engineer ruling, 4 Nov 08:25 GMT); dropping it also lets the
        // sidecar return to the v1/v2 header.
        row.designated_handoff = None;
        // ADR 0110 §4: a crypto-only exclusion frame stays as replay
        // evidence, so a survivor that missed it can still catch up after
        // this node restarts. Any other saved event is dropped.
        if !row.outgoing_event.as_deref().is_some_and(is_replay_frame) {
            row.outgoing_event = None;
        }
        row.completed_at_unix_ms = Some(now_unix_ms);
        true
    }

    /// Terminate a row (signed deletion or a verified rebind). A rebind
    /// never terminates a row that holds revocation or self-leave work.
    /// Returns whether the row changed.
    pub fn terminate(&mut self, key: &EvictionKey, cause: TerminationCause) -> bool {
        let Some(row) = self.rows.get_mut(key) else {
            return false;
        };
        if !row.phase.is_open() {
            return false;
        }
        if cause == TerminationCause::CertificateValid && !row.expiry_only() {
            return false;
        }
        row.phase = Phase::Terminated;
        row.termination = Some(cause);
        row.waiting = None;
        row.outgoing_event = None;
        // A terminated row's work is over too, so its hand-off outcome
        // goes with it, as on completion.
        row.designated_handoff = None;
        true
    }

    /// Terminate every open row of a deleted group. Returns the count.
    pub fn terminate_group(&mut self, stable_group_id: &str) -> usize {
        let keys: Vec<EvictionKey> = self
            .rows
            .values()
            .filter(|row| row.stable_group_id == stable_group_id && row.phase.is_open())
            .map(ObligationRow::key)
            .collect();
        keys.iter()
            .filter(|key| self.terminate(key, TerminationCause::GroupDeleted))
            .count()
    }

    /// Set the typed waiting state of a row. Returns whether it changed
    /// (the remaining budget alone does not count as a change).
    pub fn set_waiting(&mut self, key: &EvictionKey, waiting: Option<WaitingState>) -> bool {
        let Some(row) = self.rows.get_mut(key) else {
            return false;
        };
        let same = match (&row.waiting, &waiting) {
            (Some(a), Some(b)) => {
                a.cause == b.cause
                    && a.named == b.named
                    && a.designated_detail == b.designated_detail
            }
            (None, None) => true,
            _ => false,
        };
        row.waiting = waiting;
        !same
    }

    /// Retention (D72, D128). Drops terminated rows, drops evidence bodies
    /// of rows completed more than 30 days ago, and keeps at most
    /// [`MAX_COMPACT_RECORDS_PER_GROUP`] completed rows per group, oldest
    /// first out. Pending rows are never dropped. Returns whether the store
    /// changed.
    pub fn apply_retention(&mut self, now_unix_ms: u64) -> bool {
        let before = self.rows.len();
        self.rows.retain(|_, row| row.phase != Phase::Terminated);
        let mut changed = self.rows.len() != before;
        for row in self.rows.values_mut() {
            if row.phase != Phase::Complete || row.revocation_records.is_empty() {
                continue;
            }
            let done = row.completed_at_unix_ms.unwrap_or(now_unix_ms);
            if now_unix_ms.saturating_sub(done) >= COMPLETED_EVIDENCE_RETENTION_MS {
                row.revocation_records.clear();
                changed = true;
            }
        }
        let mut per_group: BTreeMap<String, Vec<(u64, EvictionKey)>> = BTreeMap::new();
        for (key, row) in &self.rows {
            if row.phase == Phase::Complete {
                per_group
                    .entry(row.stable_group_id.clone())
                    .or_default()
                    .push((row.completed_at_unix_ms.unwrap_or(0), key.clone()));
            }
        }
        for (_, mut completed) in per_group {
            completed.sort();
            // Replay frames: only the newest completed rows keep theirs.
            let frames_from = completed.len().saturating_sub(MAX_REPLAY_FRAMES_PER_GROUP);
            for (_, key) in completed.iter().take(frames_from) {
                if let Some(row) = self.rows.get_mut(key) {
                    if row.outgoing_event.take().is_some() {
                        changed = true;
                    }
                }
            }
            if completed.len() <= MAX_COMPACT_RECORDS_PER_GROUP {
                continue;
            }
            let excess = completed.len() - MAX_COMPACT_RECORDS_PER_GROUP;
            for (_, key) in completed.into_iter().take(excess) {
                self.rows.remove(&key);
                changed = true;
            }
        }
        changed
    }

    /// Drop every row of a group this node no longer belongs to (D128:
    /// local retention ends). Returns the count.
    pub fn forget_group(&mut self, stable_group_id: &str) -> usize {
        let before = self.rows.len();
        self.rows
            .retain(|_, row| row.stable_group_id != stable_group_id);
        before - self.rows.len()
    }
}

// ─── Certificate expiry (§1a) ──────────────────────────────────────────────

/// An admin's own expiry trigger fires once its wall clock passes the
/// selected certificate's `not_after + τ`.
#[must_use]
pub fn own_expiry_trigger_due(not_after: u64, now_unix: u64) -> bool {
    now_unix > not_after.saturating_add(EXPIRY_TOLERANCE_SECS)
}

/// A hand-off or a pre-seal re-check counts only after the node's own wall
/// clock has passed the raw `not_after`.
#[must_use]
pub fn raw_expiry_passed(not_after: u64, now_unix: u64) -> bool {
    now_unix > not_after
}

// ─── Designation and fallback (§2) ─────────────────────────────────────────

/// The designation derived from the current committed parent roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Designation {
    /// The lowest eligible admin by raw 32-byte ID (D74).
    pub designated: [u8; 32],
    /// The other eligible admins in raw-ID order; index 0 is rank 1.
    pub ranks: Vec<[u8; 32]>,
}

impl Designation {
    /// The rank of `agent`: 0 for the designated admin, r ≥ 1 for a
    /// fallback rank, `None` when not eligible.
    #[must_use]
    pub fn rank_of(&self, agent: &[u8; 32]) -> Option<usize> {
        if &self.designated == agent {
            return Some(0);
        }
        self.ranks
            .iter()
            .position(|id| id == agent)
            .map(|index| index.saturating_add(1))
    }
}

/// Derive the designation. `eligible_admins` are Active, Admin-or-higher
/// seats that pass revocation, owner-policy and containment checks
/// (certificate expiry is not evaluated, §1a). The target is never
/// designated or ranked.
#[must_use]
pub fn designate(
    eligible_admins: impl IntoIterator<Item = [u8; 32]>,
    target: &[u8; 32],
) -> Option<Designation> {
    let ordered: BTreeSet<[u8; 32]> = eligible_admins
        .into_iter()
        .filter(|id| id != target)
        .collect();
    let mut iter = ordered.into_iter();
    let designated = iter.next()?;
    Some(Designation {
        designated,
        ranks: iter.collect(),
    })
}

/// Whether this node may start the exclusion now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitPermission {
    /// This node is the designated admin.
    Designated,
    /// This node's fallback time has passed.
    Fallback {
        /// Its rank (≥ 1).
        rank: usize,
    },
    /// This node waits for the designated admin until its fallback time.
    Wait {
        /// The designated admin.
        designated: [u8; 32],
        /// The time left until this node's fallback time.
        remaining: Duration,
    },
    /// This node is not an eligible committer.
    NotEligible,
}

impl CommitPermission {
    /// Whether the node may seal now.
    #[must_use]
    pub fn may_commit(&self) -> bool {
        matches!(self, Self::Designated | Self::Fallback { .. })
    }
}

/// Decide whether `local` may start the exclusion, given the elapsed
/// monotonic budget since T_obs (§2).
#[must_use]
pub fn commit_permission(
    local: &[u8; 32],
    designation: &Designation,
    elapsed_since_t_obs: Duration,
    timing: &S4Timing,
) -> CommitPermission {
    match designation.rank_of(local) {
        None => CommitPermission::NotEligible,
        Some(0) => CommitPermission::Designated,
        Some(rank) => {
            let start = timing.fallback_offset(rank);
            if elapsed_since_t_obs >= start {
                CommitPermission::Fallback { rank }
            } else {
                CommitPermission::Wait {
                    designated: designation.designated,
                    remaining: start.saturating_sub(elapsed_since_t_obs),
                }
            }
        }
    }
}

/// Admin availability for one group (§4, D75, D126).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAvailability {
    /// At least one eligible admin exists.
    Eligible(Designation),
    /// Verified Agent-subject revocations cover every Admin-or-higher
    /// Active seat.
    AllRevoked {
        /// The revoked admin IDs.
        revoked_admins: Vec<[u8; 32]>,
    },
    /// The roster has no Active admin at all.
    NoActiveAdmin,
}

/// Classify admin availability. `active_admins` are the Admin-or-higher
/// Active seats; `is_revoked` reports a verified Agent-subject revocation;
/// `is_ineligible` reports any other failed eligibility check.
pub fn admin_availability(
    active_admins: &[[u8; 32]],
    target: &[u8; 32],
    is_revoked: impl Fn(&[u8; 32]) -> bool,
    is_ineligible: impl Fn(&[u8; 32]) -> bool,
) -> AdminAvailability {
    if active_admins.is_empty() {
        return AdminAvailability::NoActiveAdmin;
    }
    let eligible: Vec<[u8; 32]> = active_admins
        .iter()
        .filter(|id| !is_revoked(id) && !is_ineligible(id))
        .copied()
        .collect();
    if let Some(designation) = designate(eligible, target) {
        return AdminAvailability::Eligible(designation);
    }
    let mut revoked: Vec<[u8; 32]> = active_admins
        .iter()
        .filter(|id| is_revoked(id))
        .copied()
        .collect();
    revoked.sort();
    if revoked.len() == active_admins.len() {
        AdminAvailability::AllRevoked {
            revoked_admins: revoked,
        }
    } else {
        // The only eligible admin is the target itself, or the others fail
        // a non-revocation check: there is no committer, but the group is
        // not in the D75 state.
        AdminAvailability::NoActiveAdmin
    }
}

// ─── Row evaluation (§1a, §2, §3, §4) ──────────────────────────────────────

/// The inputs that decide what this node does for one open row. The
/// daemon fills it from the current committed roster under one snapshot.
#[derive(Debug, Clone)]
pub struct RowContext<'a> {
    /// This node's agent ID.
    pub local: [u8; 32],
    /// Admin-or-higher Active seats on the current roster (legacy `Owner`
    /// is Admin-equivalent).
    pub active_admins: &'a [[u8; 32]],
    /// The admins among them that hold a verified Agent-subject
    /// revocation.
    pub revoked_admins: &'a BTreeSet<[u8; 32]>,
    /// The group holds an ADR 0064 fork-quarantine marker.
    pub quarantined: bool,
    /// The target still holds an Active or Pending seat.
    pub target_seated: bool,
    /// Elapsed monotonic budget since T_obs.
    pub elapsed: Duration,
    /// This replica completed a current catch-up round (or the bounded
    /// restart sync wait).
    pub head_synced: bool,
    /// The row's latest material change is durable (or its evidence is
    /// durable elsewhere while the sidecar runs memory-only).
    pub durable: bool,
    /// This node's wall clock (Unix seconds).
    pub now_unix: u64,
    /// This node's own selected certificate is expired on its clock
    /// (`OwnerCertified` groups only).
    pub local_certificate_expired: bool,
}

/// What the worker does for a row after evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowAction {
    /// Nothing now.
    None,
    /// Remove the seated target with the ordinary signed `MemberRemoved`
    /// (and its TreeKEM removal or GSS rotation) (§3).
    CommitRemoval {
        /// 0 for the designated admin, r ≥ 1 for a fallback rank.
        rank: usize,
    },
    /// The target already left the roster and keeps a leaf: run the
    /// responsive self-leave rekey (§2 amendment to ADR 0016 §6).
    SelfLeaveRekey {
        /// 0 for the designated admin, r ≥ 1 for a fallback rank.
        rank: usize,
    },
}

/// The evaluation of one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowEvaluation {
    /// The typed wait to show (D64), `None` when the node acts.
    pub waiting: Option<WaitingState>,
    /// What the worker does.
    pub action: RowAction,
    /// The designation, when an eligible admin exists.
    pub designation: Option<Designation>,
    /// This node's commit permission, when an eligible admin exists.
    pub permission: Option<CommitPermission>,
}

impl RowEvaluation {
    fn wait(waiting: WaitingState) -> Self {
        Self {
            waiting: Some(waiting),
            action: RowAction::None,
            designation: None,
            permission: None,
        }
    }
}

/// The earliest raw `not_after` among an expiry-only row's certificates.
#[must_use]
pub fn expiry_wait_not_after(row: &ObligationRow) -> Option<u64> {
    if !row.expiry_only() {
        return None;
    }
    row.expired_certificates.values().copied().min()
}

/// Decide the typed state and the action of one open row (§2, §4).
#[must_use]
pub fn evaluate_row(row: &ObligationRow, ctx: &RowContext<'_>, timing: &S4Timing) -> RowEvaluation {
    if ctx.quarantined {
        return RowEvaluation::wait(WaitingState::cause(WaitingCause::WaitingForForkResolution));
    }
    let availability = admin_availability(
        ctx.active_admins,
        &row.target,
        |id| ctx.revoked_admins.contains(id),
        |_| false,
    );
    let designation = match availability {
        AdminAvailability::AllRevoked { revoked_admins } => {
            let mut waiting = WaitingState::cause(WaitingCause::WaitingForEligibleAdminRevocation);
            waiting.named = revoked_admins;
            return RowEvaluation::wait(waiting);
        }
        AdminAvailability::NoActiveAdmin => {
            return RowEvaluation::wait(WaitingState::cause(WaitingCause::WaitingForActiveAdmin));
        }
        AdminAvailability::Eligible(designation) => designation,
    };
    let permission = commit_permission(&ctx.local, &designation, ctx.elapsed, timing);
    let named_designated = |cause: WaitingCause| {
        let mut waiting = WaitingState::cause(cause);
        waiting.named = vec![designation.designated];
        waiting
    };
    let (waiting, action) = match &permission {
        CommitPermission::NotEligible => {
            let local_is_admin = ctx.active_admins.contains(&ctx.local);
            let cause = if local_is_admin {
                WaitingCause::LocalCommitterIneligible
            } else {
                WaitingCause::WaitingForDesignatedAdmin
            };
            (Some(named_designated(cause)), RowAction::None)
        }
        CommitPermission::Wait { remaining, .. } => {
            // §2 (L170–L171): split the designated wait on this node's
            // recorded outbound hand-off outcome against the designated
            // admin itself, not on receipts from other admins (David,
            // 4 Nov 2026; the label applies during W, rank 1 and
            // two-admin groups included). An
            // attempt that completed without reaching an
            // authenticated exchange and without a definitive routing
            // or eligibility failure is an unresolved designated
            // route; L171 lets it "preserve priority through W, not
            // forever", so the label stops at W — a higher rank's
            // stagger wait past W keeps the plain designated cause
            // (#1581 review r7). The row must have a dispatched
            // attempt: a reopened row dropped the superseded
            // attempt's record with its first-dispatch time, and an
            // attempt still in flight holds no record, so both keep
            // the plain wait. The record names its admin, so a
            // designation change voids it, and it persists in the §5
            // v3 extension, so a restart keeps the split. The
            // fallback clock itself is untouched: the rank keeps its
            // fallback time.
            let unresolved = row.first_dispatch_unix_ms.is_some()
                && ctx.elapsed < timing.designated_window
                && row.designated_handoff.is_some_and(|attempt| {
                    attempt.designated == designation.designated
                        && attempt.outcome == DesignatedHandoffOutcome::Unresolved
                });
            let mut waiting = named_designated(if unresolved {
                WaitingCause::UnresolvedDesignatedAdmin
            } else {
                WaitingCause::WaitingForDesignatedAdmin
            });
            waiting.designated_detail = Some(DesignatedWaitDetail::Rank);
            waiting.remaining_ms = Some(duration_ms(*remaining));
            (Some(waiting), RowAction::None)
        }
        CommitPermission::Designated | CommitPermission::Fallback { .. } => {
            let rank = match permission {
                CommitPermission::Fallback { rank } => rank,
                _ => 0,
            };
            if ctx.local_certificate_expired {
                (
                    Some(named_designated(WaitingCause::LocalCommitterIneligible)),
                    RowAction::None,
                )
            } else if !ctx.durable {
                (
                    Some(WaitingState::cause(WaitingCause::WaitingForDurableIntake)),
                    RowAction::None,
                )
            } else if !ctx.head_synced {
                (
                    Some(WaitingState::cause(WaitingCause::WaitingForHeadSync)),
                    RowAction::None,
                )
            } else if let Some(not_after) = expiry_wait_not_after(row)
                .filter(|not_after| !raw_expiry_passed(*not_after, ctx.now_unix))
            {
                // §1a: the pre-seal re-check found the clock no longer past
                // the raw `not_after`; the row waits, no budget renews.
                let mut waiting = WaitingState::cause(WaitingCause::WaitingForCertificateExpiry);
                waiting.remaining_ms = Some(
                    not_after
                        .saturating_sub(ctx.now_unix)
                        .saturating_add(1)
                        .saturating_mul(1000),
                );
                (Some(waiting), RowAction::None)
            } else if ctx.target_seated {
                (None, RowAction::CommitRemoval { rank })
            } else {
                (None, RowAction::SelfLeaveRekey { rank })
            }
        }
    };
    RowEvaluation {
        waiting,
        action,
        designation: Some(designation),
        permission: Some(permission),
    }
}

// ─── Monotonic budget (§2) ─────────────────────────────────────────────────

/// The elapsed budget of one row on this boot.
///
/// `consumed_before_boot` is the budget persisted by an earlier boot; the
/// in-boot part runs on the monotonic clock (`tokio::time::Instant`, so a
/// paused test clock drives it too), so a wall-clock change or a rollback
/// never renews W.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowBudget {
    /// Budget consumed by earlier boots.
    pub consumed_before_boot: Duration,
    /// The monotonic instant at which this boot started counting.
    pub counting_since: tokio::time::Instant,
}

impl RowBudget {
    /// Start counting now with `consumed_before_boot` already used.
    #[must_use]
    pub fn resume(consumed_before_boot: Duration, now: tokio::time::Instant) -> Self {
        Self {
            consumed_before_boot,
            counting_since: now,
        }
    }

    /// The elapsed budget at `now`.
    #[must_use]
    pub fn elapsed(&self, now: tokio::time::Instant) -> Duration {
        self.consumed_before_boot
            .saturating_add(now.saturating_duration_since(self.counting_since))
    }

    /// An earlier verified hand-off may shorten a budget: move T_obs back
    /// by `earlier_by`. Duplicates and retries never extend or restart it.
    pub fn shorten(&mut self, earlier_by: Duration) {
        self.consumed_before_boot = self.consumed_before_boot.saturating_add(earlier_by);
    }
}

/// Convert a duration to whole milliseconds, saturating.
#[must_use]
pub fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

// ─── Intake queue (§1 post-verification hook) ──────────────────────────────

/// One verified Agent-subject revocation, as the hook saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgentRevocation {
    /// The revoked agent.
    pub target: [u8; 32],
    /// `RevocationRecord::record_hash`.
    pub record_hash: [u8; 32],
    /// The signed record (bincode); empty when encoding failed.
    pub record_bytes: Vec<u8>,
    /// Whether it came from a startup load rather than a live route.
    pub from_startup_load: bool,
}

/// Upper bound on queued intake items. On overflow the queue drops the
/// oldest items and raises the reconcile flag, so the worker rescans the
/// whole revocation set: no verified record is lost, only batched.
pub const MAX_QUEUED_INTAKE: usize = 4096;

#[derive(Debug, Default)]
struct IntakeInner {
    queue: VecDeque<VerifiedAgentRevocation>,
    reconcile_all: bool,
    /// Records from a live route whose revocation-store write has not
    /// succeeded yet (#1765): record hash → the key of the record's
    /// `(subject, issuer)` pair (#1864). A startup-loaded record is never
    /// here.
    not_durable: BTreeMap<[u8; 32], [u8; 32]>,
    /// A task retries a failed revocation-store write for S4 (#1765).
    persist_retrying: bool,
}

/// The queue between the revocation choke point in `lib.rs` and the S4
/// worker in `x0xd`. Cloning shares the queue.
///
/// The hook only enqueues; it never takes membership or persistence locks,
/// so the revocation-set lock is released before S4 takes them (§1).
#[derive(Debug, Clone, Default)]
pub struct RevocationIntake {
    inner: std::sync::Arc<std::sync::Mutex<IntakeInner>>,
    notify: std::sync::Arc<tokio::sync::Notify>,
    /// Cancelled when the owning Agent shuts down: no S4 store-write
    /// retry starts again after that (#1765).
    persist_stop: tokio_util::sync::CancellationToken,
}

impl RevocationIntake {
    /// A new, empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The post-verification hook: call after `verify_and_insert` returned
    /// `Ok(true)`. Only Agent subjects schedule seat exclusion; every other
    /// subject is ignored here (its serving denial is immediate elsewhere).
    pub fn note_verified(&self, record: &crate::revocation::RevocationRecord) {
        self.note_verified_from(record, false);
    }

    /// The startup-load hook: every loaded record was verified by
    /// `verify_and_insert` while decoding the store.
    pub fn note_loaded(&self, record: &crate::revocation::RevocationRecord) {
        self.note_verified_from(record, true);
    }

    fn note_verified_from(
        &self,
        record: &crate::revocation::RevocationRecord,
        from_startup_load: bool,
    ) {
        let crate::revocation::RevokedSubject::Agent(agent) = &record.subject else {
            return;
        };
        let record_hash = record.record_hash();
        let item = VerifiedAgentRevocation {
            target: *agent.as_bytes(),
            record_hash,
            record_bytes: bincode::serialize(record).unwrap_or_default(),
            from_startup_load,
        };
        {
            let mut inner = self.lock();
            if !from_startup_load {
                // An Agent subject always has a pair key; the record hash
                // stands in when it has none, and then only the record
                // itself makes it durable.
                inner
                    .not_durable
                    .insert(record_hash, record.pair_key().unwrap_or(record_hash));
            }
            if inner.queue.len() >= MAX_QUEUED_INTAKE {
                inner.queue.pop_front();
                inner.reconcile_all = true;
            }
            inner.queue.push_back(item);
        }
        self.notify.notify_one();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, IntakeInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ask the worker for a full reconciliation pass.
    pub fn request_reconcile(&self) {
        self.lock().reconcile_all = true;
        self.notify.notify_one();
    }

    /// The live-route record hashes whose revocation-store write has not
    /// succeeded yet. Take this before the store snapshot is encoded:
    /// every hash in it is then in the snapshot (#1765).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn not_durable_hashes(&self) -> BTreeSet<[u8; 32]> {
        self.lock().not_durable.keys().copied().collect()
    }

    /// [`Self::not_durable_hashes`] with the pair key of each record
    /// (#1864). The revocation set keeps one record per pair, so a
    /// waiting record can be replaced before its store write. Its
    /// evidence is then on disk when the kept record of its pair is.
    #[must_use]
    pub(crate) fn not_durable_pairs(&self) -> BTreeMap<[u8; 32], [u8; 32]> {
        self.lock().not_durable.clone()
    }

    /// The revocation-store write that held `hashes` succeeded: they are
    /// durable now. The worker wakes, so a row held for them re-evaluates.
    pub(crate) fn note_durable(&self, hashes: &BTreeSet<[u8; 32]>) {
        if hashes.is_empty() {
            return;
        }
        self.lock()
            .not_durable
            .retain(|hash, _| !hashes.contains(hash));
        self.notify.notify_one();
    }

    /// Whether every one of `hashes` is in the revocation store on disk
    /// (ADR 0110 "Memory-only durability"). A record that a live route
    /// verified stays not durable until its store write succeeds.
    #[must_use]
    pub(crate) fn all_durable(&self, hashes: &BTreeSet<[u8; 32]>) -> bool {
        let inner = self.lock();
        !hashes
            .iter()
            .any(|hash| inner.not_durable.contains_key(hash))
    }

    /// Become the one task that retries a failed revocation-store write.
    /// `false` when a task already retries: it reads the pending hashes
    /// again on each attempt, so it also writes the caller's records.
    #[must_use]
    pub(crate) fn claim_persist_retry(&self) -> bool {
        let mut inner = self.lock();
        if inner.persist_retrying {
            return false;
        }
        inner.persist_retrying = true;
        true
    }

    /// The retry task stops. A write that fails after this starts a new one.
    pub(crate) fn release_persist_retry(&self) {
        self.lock().persist_retrying = false;
    }

    /// The owning Agent shuts down. A retry task stops before its next
    /// attempt; a write in progress finishes.
    pub(crate) fn stop_persist_retries(&self) {
        self.persist_stop.cancel();
    }

    /// The signal of [`Self::stop_persist_retries`].
    pub(crate) fn persist_stop(&self) -> &tokio_util::sync::CancellationToken {
        &self.persist_stop
    }

    /// Whether a retry task holds the claim.
    #[cfg(test)]
    pub(crate) fn persist_retrying_for_testing(&self) -> bool {
        self.lock().persist_retrying
    }

    /// Take every queued item and the reconcile flag.
    #[must_use]
    pub fn drain(&self) -> (Vec<VerifiedAgentRevocation>, bool) {
        let mut inner = self.lock();
        let items = inner.queue.drain(..).collect();
        let reconcile = std::mem::take(&mut inner.reconcile_all);
        (items, reconcile)
    }

    /// The wake-up signal for the worker.
    #[must_use]
    pub fn notified(&self) -> std::sync::Arc<tokio::sync::Notify> {
        std::sync::Arc::clone(&self.notify)
    }
}

// ─── Persistence (§5) ──────────────────────────────────────────────────────

/// File name of the S4 obligation sidecar in `<data_dir>`.
pub const EVS_FILE_NAME: &str = "revocation-evictions.evs";
/// Extension of the per-group S4 journal in `<data_dir>/treekem/`.
pub const EVJOURNAL_EXTENSION: &str = "evjournal";
/// The `.evs` family prefix, reserved for this path forever.
pub const EVS_PREFIX: &[u8] = b"X0XEVICT";
/// The `.evjournal` family prefix, reserved for this path forever.
pub const EVJOURNAL_PREFIX: &[u8] = b"X0XEVJ";
/// The `.evs` v1 header (10 bytes).
pub const EVS_HEADER_V1: &[u8; 10] = b"X0XEVICT1\0";
/// The `.evs` v2 header (10 bytes): the v1 body followed by
/// [`EvsQueuedBansV2`]. It is written only while a queued manual ban
/// exists, so a store without one stays v1 and readable by a v1 binary.
pub const EVS_HEADER_V2: &[u8; 10] = b"X0XEVICT2\0";
/// The `.evs` v3 header (10 bytes): the v2 body followed by this node's
/// recorded designated hand-off outcomes. It is written only while some
/// open row holds an `unresolved` or `unsupported` hand-off outcome
/// inside W against its current designated admin — a routine
/// `exchange_reached` never rides the file, and the record is dropped
/// at W, on a designation change and when the row closes or reopens
/// (Engineer rulings, 4 Nov 2026 08:25 and 17:22 GMT) — so a store
/// without such a record stays v1 or v2 and readable by a v1 or v2
/// binary. A binary older than v3 reads a v3 file as a newer format
/// and runs S4 memory-only for that whole run: it never rewrites a
/// newer file, so only a v3-reading binary returns it to v1/v2.
pub const EVS_HEADER_V3: &[u8; 10] = b"X0XEVICT3\0";
/// The `.evjournal` v1 header (8 bytes).
pub const EVJOURNAL_HEADER_V1: &[u8; 8] = b"X0XEVJ1\0";
/// The highest `.evjournal` layout version this binary reads.
pub const SIDECAR_MAX_SUPPORTED_VERSION: u8 = 1;
/// The highest `.evs` layout version this binary reads.
pub const EVS_MAX_SUPPORTED_VERSION: u8 = 3;

/// Why an S4 file could not be used (ADR 0108 §5a classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidecarDecodeError {
    /// The file is damaged; S4 quarantines it and rebuilds.
    Damaged(&'static str),
    /// The file has a newer layout; this binary never rewrites it.
    NewerFormat(u8),
}

impl std::fmt::Display for SidecarDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Damaged(reason) => write!(f, "damaged S4 file: {reason}"),
            Self::NewerFormat(version) => write!(f, "newer S4 file layout v{version}"),
        }
    }
}

impl std::error::Error for SidecarDecodeError {}

/// The frozen v1 `.evs` body. It begins with `rebuilt_from`, the §5a
/// `txid` list.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvsBodyV1 {
    /// Transaction IDs of the §5a rebuilds this file came from.
    pub rebuilt_from: Vec<[u8; 16]>,
    /// The obligation rows.
    pub rows: Vec<ObligationRow>,
}

/// One manual ban that a non-designated admin accepted with `202 queued`
/// (ADR 0110 §2 amendment to ADR 0016 §6). It is applied as a ban after
/// the designated removal, or at this node's fallback time, and it must
/// survive a restart (ADR 0110 follow-up "a queued manual ban is still
/// applied after the designated removal").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedBanV1 {
    /// Stable group ID.
    pub stable_group_id: String,
    /// The agent to ban.
    pub target: [u8; 32],
    /// When the request was accepted (Unix ms).
    pub queued_at_unix_ms: u64,
}

/// The `.evs` v2 extension that follows the v1 body.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvsQueuedBansV2 {
    /// Accepted manual bans that are not applied yet.
    pub queued_bans: Vec<QueuedBanV1>,
}

/// One persisted designated-admin hand-off outcome, keyed by its row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DesignatedHandoffV3 {
    /// Stable group ID of the row.
    pub stable_group_id: String,
    /// Target agent ID of the row.
    pub target: [u8; 32],
    /// The recorded outcome and the designated admin it names.
    pub record: DesignatedHandoffRecord,
}

/// The `.evs` v3 extension that follows the v2 body (§2, L170–L173):
/// this node's recorded outbound hand-off outcome against each row's
/// designated admin, so the `unresolved_designated_admin` split and the
/// §4 downgrade survive a restart. Only `unresolved` and `unsupported`
/// outcomes ride it (Engineer ruling, 4 Nov 2026 08:25 GMT).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct EvsDesignatedHandoffsV3 {
    /// One recorded outcome per row that holds one.
    pub handoffs: Vec<DesignatedHandoffV3>,
}

/// The frozen v1 `.evjournal` body: one prepared S4 transition (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvJournalV1 {
    /// Transaction ID.
    pub txid: [u8; 16],
    /// Stable group ID.
    pub stable_group_id: String,
    /// Target agent ID.
    pub target: [u8; 32],
    /// The parent head the transition extends.
    pub parent_head: String,
    /// The roster revision after the transition.
    pub next_revision: u64,
    /// The epoch after the transition, when the plane has one.
    pub result_epoch: Option<u64>,
    /// Trigger hashes that authorize the transition.
    pub evidence: Vec<[u8; 32]>,
    /// The exact outgoing event: the signed `X0XCE1` frame of a
    /// crypto-only exclusion, or the JSON `MemberRemoved` (with its
    /// TreeKEM commit and signed state commit) of a seated-target
    /// removal. A seated-target journal is first written empty; the
    /// removal path rewrites it with the event before the new epoch
    /// commits. Empty means no event was prepared yet.
    pub outgoing_event: Vec<u8>,
    /// The head the transition produces, when it is known before the
    /// legacy commit. A restart compares it with the verified chain to
    /// tell a committed result from a competing branch (§3).
    pub result_head: Option<String>,
}

/// Split and check a `<prefix><digit>\0` header. Returns the version and
/// the body.
fn split_header<'a>(
    bytes: &'a [u8],
    prefix: &[u8],
    max_version: u8,
) -> Result<(u8, &'a [u8]), SidecarDecodeError> {
    let header_len = prefix.len() + 2;
    let Some(found_prefix) = bytes.get(..prefix.len()) else {
        if prefix.starts_with(bytes) && !bytes.is_empty() {
            return Err(SidecarDecodeError::Damaged("truncated_header"));
        }
        return Err(SidecarDecodeError::Damaged("missing_prefix"));
    };
    if found_prefix != prefix {
        return Err(SidecarDecodeError::Damaged("missing_prefix"));
    }
    let (Some(&version_byte), Some(&terminator), Some(body)) = (
        bytes.get(prefix.len()),
        bytes.get(prefix.len() + 1),
        bytes.get(header_len..),
    ) else {
        return Err(SidecarDecodeError::Damaged("truncated_header"));
    };
    if !(b'1'..=b'9').contains(&version_byte) {
        return Err(SidecarDecodeError::Damaged("bad_version"));
    }
    if terminator != 0 {
        return Err(SidecarDecodeError::Damaged("missing_nul"));
    }
    let version = version_byte - b'0';
    if version > max_version {
        return Err(SidecarDecodeError::NewerFormat(version));
    }
    Ok((version, body))
}

/// The ADR 0108 §5a pending-copy name of a quarantined file:
/// `<file>.q-<txid>-<h>.pending`, where `h` is the first 16 bytes of
/// BLAKE3 over the bytes read at classification.
#[must_use]
pub fn quarantine_pending_name(file_name: &str, txid: &[u8; 16], bytes: &[u8]) -> String {
    format!(
        "{file_name}.q-{}-{}.pending",
        hex::encode(txid),
        quarantine_hash_hex(bytes)
    )
}

/// The ADR 0108 §5a history name: the pending name without `.pending`.
#[must_use]
pub fn quarantine_history_name(pending_name: &str) -> Option<&str> {
    pending_name.strip_suffix(".pending")
}

/// Hex of the first 16 bytes of BLAKE3 over `bytes` (ADR 0108 §5a `h`).
#[must_use]
pub fn quarantine_hash_hex(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    let short = digest.as_bytes().get(..16).unwrap_or_default();
    hex::encode(short)
}

/// Parse `<file>.q-<txid>-<h>.pending` into `(txid, h)`.
#[must_use]
pub fn parse_quarantine_pending_name(
    file_name: &str,
    candidate: &str,
) -> Option<([u8; 16], String)> {
    let rest = candidate
        .strip_prefix(file_name)?
        .strip_prefix(".q-")?
        .strip_suffix(".pending")?;
    let (txid_hex, h) = rest.split_once('-')?;
    let mut txid = [0u8; 16];
    hex::decode_to_slice(txid_hex, &mut txid).ok()?;
    if h.len() != 32 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((txid, h.to_string()))
}

/// Decode a postcard body that must be consumed exactly.
fn decode_exact<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, SidecarDecodeError> {
    let (value, rest) = postcard::take_from_bytes::<T>(body)
        .map_err(|_| SidecarDecodeError::Damaged("body_decode"))?;
    if !rest.is_empty() {
        return Err(SidecarDecodeError::Damaged("trailing_bytes"));
    }
    Ok(value)
}

/// Encode the `.evs` sidecar.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_evs(body: &EvsBodyV1) -> Result<Vec<u8>, postcard::Error> {
    encode_evs_with_queued_bans(body, &[])
}

/// Encode the `.evs` sidecar with its queued manual bans. With no queued
/// ban the file is v1; otherwise it is v2 (the v1 body, then
/// [`EvsQueuedBansV2`]).
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_evs_with_queued_bans(
    body: &EvsBodyV1,
    queued_bans: &[QueuedBanV1],
) -> Result<Vec<u8>, postcard::Error> {
    if queued_bans.is_empty() {
        let mut out = EVS_HEADER_V1.to_vec();
        out.extend(postcard::to_stdvec(body)?);
        return Ok(out);
    }
    let mut out = EVS_HEADER_V2.to_vec();
    out.extend(postcard::to_stdvec(body)?);
    out.extend(postcard::to_stdvec(&EvsQueuedBansV2 {
        queued_bans: queued_bans.to_vec(),
    })?);
    Ok(out)
}

/// Decode the `.evs` sidecar (the rows only).
///
/// # Errors
///
/// Returns the §5a classification of a file that cannot be used.
pub fn decode_evs(bytes: &[u8]) -> Result<EvsBodyV1, SidecarDecodeError> {
    decode_evs_with_queued_bans(bytes).map(|(body, _)| body)
}

/// Encode the `.evs` sidecar with its queued manual bans and designated
/// hand-off outcomes. With no outcome-bearing record the file is v1 (no
/// queued ban) or v2 (the v1 body, then [`EvsQueuedBansV2`]); with any
/// `unresolved` or `unsupported` outcome it is v3 (the v2 body, then
/// [`EvsDesignatedHandoffsV3`]). A routine `exchange_reached` must not
/// reach `handoffs` (Engineer ruling, 4 Nov 2026 08:25 GMT).
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub(crate) fn encode_evs_with_extensions(
    body: &EvsBodyV1,
    queued_bans: &[QueuedBanV1],
    handoffs: &[DesignatedHandoffV3],
) -> Result<Vec<u8>, postcard::Error> {
    if handoffs.is_empty() {
        return encode_evs_with_queued_bans(body, queued_bans);
    }
    let mut out = EVS_HEADER_V3.to_vec();
    out.extend(postcard::to_stdvec(body)?);
    out.extend(postcard::to_stdvec(&EvsQueuedBansV2 {
        queued_bans: queued_bans.to_vec(),
    })?);
    out.extend(postcard::to_stdvec(&EvsDesignatedHandoffsV3 {
        handoffs: handoffs.to_vec(),
    })?);
    Ok(out)
}

/// Decode the `.evs` sidecar with its queued manual bans (empty for v1).
/// A v3 file's designated hand-off outcomes are applied onto their rows
/// (§2): a row without an entry loads with the `None` default, and an
/// entry whose row is absent is dropped.
///
/// # Errors
///
/// Returns the §5a classification of a file that cannot be used.
pub fn decode_evs_with_queued_bans(
    bytes: &[u8],
) -> Result<(EvsBodyV1, Vec<QueuedBanV1>), SidecarDecodeError> {
    let (version, body) = split_header(bytes, EVS_PREFIX, EVS_MAX_SUPPORTED_VERSION)?;
    if version == 1 {
        return decode_exact(body).map(|rows| (rows, Vec::new()));
    }
    let (rows, rest) = postcard::take_from_bytes::<EvsBodyV1>(body)
        .map_err(|_| SidecarDecodeError::Damaged("body_decode"))?;
    let (extension, rest) = postcard::take_from_bytes::<EvsQueuedBansV2>(rest)
        .map_err(|_| SidecarDecodeError::Damaged("extension_decode"))?;
    let handoffs = if version >= 3 {
        decode_exact::<EvsDesignatedHandoffsV3>(rest)?
    } else if !rest.is_empty() {
        return Err(SidecarDecodeError::Damaged("trailing_bytes"));
    } else {
        EvsDesignatedHandoffsV3::default()
    };
    let mut body = rows;
    for handoff in handoffs.handoffs {
        if let Some(row) = body.rows.iter_mut().find(|row| {
            row.stable_group_id == handoff.stable_group_id && row.target == handoff.target
        }) {
            row.designated_handoff = Some(handoff.record);
        }
    }
    Ok((body, extension.queued_bans))
}

/// Encode one `.evjournal`.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_evjournal(journal: &EvJournalV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = EVJOURNAL_HEADER_V1.to_vec();
    out.extend(postcard::to_stdvec(journal)?);
    Ok(out)
}

/// Decode one `.evjournal`.
///
/// # Errors
///
/// Returns the §5a classification of a file that cannot be used.
pub fn decode_evjournal(bytes: &[u8]) -> Result<EvJournalV1, SidecarDecodeError> {
    let (_, body) = split_header(bytes, EVJOURNAL_PREFIX, SIDECAR_MAX_SUPPORTED_VERSION)?;
    decode_exact(body)
}

// ─── §4 EvictionHandoffV1 wire ─────────────────────────────────────────────

/// Typed prefix of an `EvictionHandoffV1` direct message (§4).
pub const EVICTION_HANDOFF_PREFIX: &[u8] = b"X0XEVH1";

/// At most this many signed revocation records ride in one hand-off.
pub const MAX_HANDOFF_REVOCATION_RECORDS: usize = 16;

/// The target's expired committed certificate in a hand-off (§1a).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffExpiredCertificate {
    /// `owner_cert::certificate_digest_hex` of the committed certificate.
    pub certificate_digest: String,
    /// Its bytes (bincode `AgentCertificate`), when the sender holds them.
    pub certificate_bytes: Option<Vec<u8>>,
}

/// The frozen v1 `EvictionHandoffV1` body (§4). It is advisory evidence:
/// the receiver verifies every record and the current chain and authority
/// on its own, deduplicates by the §1 key, and schedules only a verified
/// trigger. It carries no key material. The direct-message carrier
/// authenticates the sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionHandoffV1 {
    /// Stable group ID.
    pub stable_group_id: String,
    /// Target agent ID.
    pub target: [u8; 32],
    /// The parent head the sender observed.
    pub observed_parent_head: String,
    /// Signed revocation records (bincode `RevocationRecord`).
    pub revocation_records: Vec<Vec<u8>>,
    /// The head of a verified self-leave on the sender's chain.
    pub self_leave_commit: Option<String>,
    /// The target's expired committed certificate.
    pub expired_certificate: Option<HandoffExpiredCertificate>,
    /// A renewed certificate for the target's seat, sent by the seat's own
    /// agent after its self-rebind cutoff (§4a).
    pub renewed_certificate: Option<Vec<u8>>,
}

impl EvictionHandoffV1 {
    /// Whether the body carries at least one piece of evidence.
    #[must_use]
    pub fn has_evidence(&self) -> bool {
        !self.revocation_records.is_empty()
            || self.self_leave_commit.is_some()
            || self.expired_certificate.is_some()
            || self.renewed_certificate.is_some()
    }
}

/// Why a hand-off was refused at decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffDecodeError {
    /// Not an `X0XEVH1` payload.
    WrongPrefix,
    /// The body did not decode or was not consumed exactly.
    Malformed,
    /// The body carries no evidence or too many records.
    OutOfBounds,
}

/// Encode a hand-off as a direct-message payload.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_handoff(handoff: &EvictionHandoffV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = EVICTION_HANDOFF_PREFIX.to_vec();
    out.extend(postcard::to_stdvec(handoff)?);
    Ok(out)
}

/// Decode a hand-off payload with exact consumption.
///
/// # Errors
///
/// Returns why the payload is refused.
pub fn decode_handoff(payload: &[u8]) -> Result<EvictionHandoffV1, HandoffDecodeError> {
    let body = payload
        .strip_prefix(EVICTION_HANDOFF_PREFIX)
        .ok_or(HandoffDecodeError::WrongPrefix)?;
    let (handoff, rest) = postcard::take_from_bytes::<EvictionHandoffV1>(body)
        .map_err(|_| HandoffDecodeError::Malformed)?;
    if !rest.is_empty() {
        return Err(HandoffDecodeError::Malformed);
    }
    if !handoff.has_evidence() || handoff.revocation_records.len() > MAX_HANDOFF_REVOCATION_RECORDS
    {
        return Err(HandoffDecodeError::OutOfBounds);
    }
    Ok(handoff)
}

/// The S4 file states shown on status (ADR 0108 §5a generic states).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SidecarState {
    /// The file is absent or decoded; writes are durable.
    Ok,
    /// The file is damaged and was quarantined; S4 rebuilt it.
    Rebuilt,
    /// The file could not be read; S4 runs memory-only.
    SidecarUnavailable,
    /// The file has a newer layout; S4 runs memory-only and never rewrites
    /// it.
    SidecarNewerFormat,
    /// Quarantine failed; S4 runs memory-only.
    SidecarQuarantineFailed,
}

impl SidecarState {
    /// Whether S4 may write the file.
    #[must_use]
    pub fn writable(self) -> bool {
        matches!(self, Self::Ok | Self::Rebuilt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn key(target: u8) -> EvictionKey {
        EvictionKey::new("group", id(target))
    }

    fn revocation(hash: u8) -> EvictionTrigger {
        EvictionTrigger::AgentRevocation {
            record_hash: id(hash),
            record_bytes: vec![hash],
        }
    }

    #[test]
    fn timing_defaults_are_measured_and_not_rejected_values() {
        let timing = S4Timing::default();
        assert_eq!(timing.designated_window, Duration::from_secs(18));
        assert_eq!(timing.fallback_stagger, Duration::from_secs(11));
        assert_eq!(timing.restart_sync_wait, Duration::from_secs(13));
        assert_ne!(timing.designated_window, Duration::from_secs(2));
        assert_ne!(timing.completion_bound, Duration::from_secs(5));
        assert_eq!(timing.fallback_offset(0), Duration::ZERO);
        assert_eq!(timing.fallback_offset(1), timing.designated_window);
        assert_eq!(
            timing.fallback_offset(3),
            timing.designated_window + timing.fallback_stagger * 2
        );
    }

    #[test]
    fn intake_dedupes_and_never_extends_window() {
        let mut store = ObligationStore::new();
        let k = key(9);
        assert_eq!(
            store.intake(&k, revocation(1), None, 1_000, [0; 16]),
            IntakeOutcome::Created
        );
        assert_eq!(
            store.intake(&k, revocation(1), None, 5_000, [0; 16]),
            IntakeOutcome::Duplicate
        );
        assert_eq!(
            store.intake(&k, revocation(2), None, 6_000, [0; 16]),
            IntakeOutcome::AddedEvidence
        );
        let row = store.get(&k).expect("row");
        assert_eq!(row.observed_at_unix_ms, 1_000);
        assert_eq!(row.revocation_hashes.len(), 2);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn completed_row_is_not_reopened_by_duplicate_or_same_incarnation() {
        let mut store = ObligationStore::new();
        let k = key(9);
        store.intake(&k, revocation(1), Some("leaf-a"), 1, [0; 16]);
        assert!(store.complete(&k, Some("head".into()), Some(4), 2));
        assert_eq!(
            store.intake(&k, revocation(1), Some("leaf-a"), 3, [0; 16]),
            IntakeOutcome::Duplicate
        );
        assert_eq!(
            store.intake(&k, revocation(2), Some("leaf-a"), 3, [0; 16]),
            IntakeOutcome::AddedEvidence
        );
        assert_eq!(store.get(&k).expect("row").phase, Phase::Complete);
    }

    /// #1508 review (Codex P1 on a00455a): every trigger kind of a new
    /// membership incarnation reopens completed work, and a trigger of the
    /// old incarnation (a replay of the old departure) does not.
    #[test]
    fn every_trigger_of_a_new_incarnation_reopens_completed_work() {
        let leave = |hash: &str| EvictionTrigger::SelfLeave {
            commit_hash: hash.into(),
        };
        let expiry = |digest: &str| EvictionTrigger::CertificateExpiry {
            certificate_digest: digest.into(),
            not_after: 10,
        };
        let cases: [(EvictionTrigger, EvictionTrigger, EvictionTrigger); 3] = [
            (revocation(1), revocation(1), revocation(1)),
            (leave("h1"), leave("h1-later-head"), leave("h2")),
            (expiry("d1"), expiry("d1"), expiry("d2")),
        ];
        for (first, replay, second) in cases {
            let mut store = ObligationStore::new();
            let k = key(9);
            store.intake(&k, first, Some("seat-a"), 1, [0; 16]);
            assert!(store.complete(&k, None, None, 2));
            assert_ne!(
                store.intake(&k, replay, Some("seat-a"), 3, [0; 16]),
                IntakeOutcome::Reopened,
                "a replay of the old incarnation"
            );
            assert_eq!(store.get(&k).expect("row").phase, Phase::Complete);
            assert_eq!(
                store.intake(&k, second.clone(), Some("seat-b"), 4, [0; 16]),
                IntakeOutcome::Reopened,
                "{second:?} of a new incarnation"
            );
            let row = store.get(&k).expect("row");
            assert_eq!(row.phase, Phase::Pending);
            assert_eq!(row.incarnation.as_deref(), Some("seat-b"));
            assert_eq!(row.observed_at_unix_ms, 4, "T_obs restarts");
            if let EvictionTrigger::SelfLeave { commit_hash } = &second {
                assert!(
                    row.self_leave_commits.contains(commit_hash),
                    "the new departure is the row's leave evidence"
                );
            }
        }
    }

    #[test]
    fn renewal_terminates_expiry_only_and_revocation_reopens() {
        let mut store = ObligationStore::new();
        let k = key(9);
        let expiry = EvictionTrigger::CertificateExpiry {
            certificate_digest: "d".into(),
            not_after: 10,
        };
        store.intake(&k, expiry, None, 1, [0; 16]);
        assert!(store.terminate(&k, TerminationCause::CertificateValid));
        assert_eq!(
            store.intake(&k, revocation(1), None, 2, [0; 16]),
            IntakeOutcome::Reopened
        );
        // A renewal never cancels revocation work.
        assert!(!store.terminate(&k, TerminationCause::CertificateValid));
        assert!(store.get(&k).expect("row").phase.is_open());
    }

    #[test]
    fn retention_keeps_pending_and_drops_old_evidence() {
        let mut store = ObligationStore::new();
        store.intake(&key(1), revocation(1), None, 0, [0; 16]);
        store.intake(&key(2), revocation(2), None, 0, [0; 16]);
        store.complete(&key(2), None, None, 0);
        store.intake(&key(3), revocation(3), None, 0, [0; 16]);
        store.terminate_group("other");
        assert!(store.apply_retention(COMPLETED_EVIDENCE_RETENTION_MS));
        assert!(
            store
                .get(&key(1))
                .expect("pending")
                .revocation_records
                .len()
                == 1
        );
        assert!(store
            .get(&key(2))
            .expect("done")
            .revocation_records
            .is_empty());
        assert!(store.terminate_group("group") == 2);
        assert!(store.apply_retention(COMPLETED_EVIDENCE_RETENTION_MS));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn designation_is_lowest_eligible_and_excludes_target() {
        let designation = designate([id(5), id(2), id(9), id(3)], &id(2)).expect("some");
        assert_eq!(designation.designated, id(3));
        assert_eq!(designation.ranks, vec![id(5), id(9)]);
        assert_eq!(designation.rank_of(&id(9)), Some(2));
        assert_eq!(designation.rank_of(&id(2)), None);
        assert!(designate([id(2)], &id(2)).is_none());
    }

    #[test]
    fn fallback_ranks_are_staggered() {
        let timing = S4Timing::default();
        let designation = designate([id(1), id(2), id(3)], &id(9)).expect("some");
        assert_eq!(
            commit_permission(&id(1), &designation, Duration::ZERO, &timing),
            CommitPermission::Designated
        );
        let before = timing.designated_window - Duration::from_millis(1);
        assert!(matches!(
            commit_permission(&id(2), &designation, before, &timing),
            CommitPermission::Wait { designated, .. } if designated == id(1)
        ));
        assert_eq!(
            commit_permission(&id(2), &designation, timing.designated_window, &timing),
            CommitPermission::Fallback { rank: 1 }
        );
        assert!(
            !commit_permission(&id(3), &designation, timing.designated_window, &timing)
                .may_commit()
        );
        assert!(commit_permission(
            &id(3),
            &designation,
            timing.designated_window + timing.fallback_stagger,
            &timing
        )
        .may_commit());
        assert_eq!(
            commit_permission(&id(7), &designation, Duration::MAX, &timing),
            CommitPermission::NotEligible
        );
    }

    #[test]
    fn admin_availability_classifies_all_revoked() {
        let admins = [id(1), id(2)];
        assert!(matches!(
            admin_availability(&admins, &id(9), |a| a == &id(1), |_| false),
            AdminAvailability::Eligible(d) if d.designated == id(2)
        ));
        assert_eq!(
            admin_availability(&admins, &id(9), |_| true, |_| false),
            AdminAvailability::AllRevoked {
                revoked_admins: vec![id(1), id(2)]
            }
        );
        assert_eq!(
            admin_availability(&[], &id(9), |_| false, |_| false),
            AdminAvailability::NoActiveAdmin
        );
    }

    #[test]
    fn expiry_checks_use_tau() {
        assert!(!own_expiry_trigger_due(100, 100 + EXPIRY_TOLERANCE_SECS));
        assert!(own_expiry_trigger_due(100, 101 + EXPIRY_TOLERANCE_SECS));
        assert!(!raw_expiry_passed(100, 100));
        assert!(raw_expiry_passed(100, 101));
    }

    #[test]
    fn budget_survives_restart_and_shortens_only() {
        let now = tokio::time::Instant::now();
        let mut budget = RowBudget::resume(Duration::from_secs(4), now);
        assert_eq!(budget.elapsed(now), Duration::from_secs(4));
        budget.shorten(Duration::from_secs(1));
        assert_eq!(budget.elapsed(now), Duration::from_secs(5));
    }

    #[test]
    fn waiting_cause_strings_match_serde() {
        for cause in [
            WaitingCause::WaitingForDurableIntake,
            WaitingCause::WaitingForDesignatedAdmin,
            WaitingCause::UnresolvedDesignatedAdmin,
            WaitingCause::WaitingForHeadSync,
            WaitingCause::WaitingForMemberKeyPackage,
            WaitingCause::WaitingForForkResolution,
            WaitingCause::WaitingForReceiverUpgrade,
            WaitingCause::LocalCommitterIneligible,
            WaitingCause::WaitingForEligibleAdminRevocation,
            WaitingCause::WaitingForActiveAdmin,
            WaitingCause::WaitingForAdminCertificateRenewal,
            WaitingCause::WaitingForCertificateEvidence,
            WaitingCause::WaitingForHostCommit,
            WaitingCause::RebuildingObligationStore,
            WaitingCause::WaitingForCertificateExpiry,
        ] {
            let json = serde_json::to_string(&cause).expect("json");
            assert_eq!(json, format!("\"{}\"", cause.as_str()));
        }
    }

    #[test]
    fn intake_queue_keeps_agent_subjects_only() {
        let kp = crate::identity::AgentKeypair::generate().expect("kp");
        let intake = RevocationIntake::new();
        let agent_record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(kp.agent_id()),
            kp.public_key(),
            kp.secret_key(),
            1,
            None,
        )
        .expect("sign");
        let machine_record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(crate::identity::MachineId([3; 32])),
            kp.public_key(),
            kp.secret_key(),
            1,
            None,
        )
        .expect("sign");
        intake.note_verified(&machine_record);
        intake.note_verified(&agent_record);
        intake.note_loaded(&agent_record);
        let (items, reconcile) = intake.drain();
        assert!(!reconcile);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].target, *kp.agent_id().as_bytes());
        assert!(!items[0].from_startup_load);
        assert!(items[1].from_startup_load);
    }

    /// #1765: a live-route record is not durable until its store write
    /// succeeds; a loaded record and a later record are tracked apart.
    #[test]
    fn a_live_revocation_is_durable_only_after_its_store_write() {
        let sign = |seq| {
            let kp = crate::identity::AgentKeypair::generate().expect("kp");
            crate::revocation::RevocationRecord::sign(
                crate::revocation::RevokedSubject::Agent(kp.agent_id()),
                kp.public_key(),
                kp.secret_key(),
                seq,
                None,
            )
            .expect("sign")
        };
        let intake = RevocationIntake::new();
        let (live, loaded, later) = (sign(1), sign(2), sign(3));
        let hashes = |records: &[&crate::revocation::RevocationRecord]| {
            records
                .iter()
                .map(|record| record.record_hash())
                .collect::<BTreeSet<_>>()
        };
        intake.note_loaded(&loaded);
        assert!(intake.all_durable(&hashes(&[&loaded])));
        intake.note_verified(&live);
        assert!(!intake.all_durable(&hashes(&[&live, &loaded])));
        // The write that took this snapshot fails: nothing changes.
        let snapshot = intake.not_durable_hashes();
        assert_eq!(snapshot, hashes(&[&live]));
        // A record verified after the snapshot is not in its bytes.
        intake.note_verified(&later);
        intake.note_durable(&snapshot);
        assert!(intake.all_durable(&hashes(&[&live, &loaded])));
        assert!(!intake.all_durable(&hashes(&[&later])));
        assert_eq!(intake.not_durable_hashes(), hashes(&[&later]));
    }

    fn sample_row() -> ObligationRow {
        let mut store = ObligationStore::new();
        store.intake(&key(4), revocation(7), Some("kp"), 11, [2; 16]);
        store.get(&key(4)).expect("row").clone()
    }

    #[test]
    fn evs_round_trips_and_rejects_trailing_bytes() {
        let body = EvsBodyV1 {
            rebuilt_from: vec![[1; 16]],
            rows: vec![sample_row()],
        };
        let bytes = encode_evs(&body).expect("encode");
        assert_eq!(&bytes[..10], EVS_HEADER_V1);
        assert_eq!(decode_evs(&bytes).expect("decode"), body);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_evs(&trailing),
            Err(SidecarDecodeError::Damaged("trailing_bytes"))
        );
    }

    #[test]
    fn evs_header_damage_forms_are_classified() {
        let bytes = encode_evs(&EvsBodyV1::default()).expect("encode");
        assert_eq!(
            decode_evs(b"garbage-file"),
            Err(SidecarDecodeError::Damaged("missing_prefix"))
        );
        assert_eq!(
            decode_evs(&bytes[..9]),
            Err(SidecarDecodeError::Damaged("truncated_header"))
        );
        assert_eq!(
            decode_evs(b"X0XEV"),
            Err(SidecarDecodeError::Damaged("truncated_header"))
        );
        let mut zero = bytes.clone();
        zero[8] = b'0';
        assert_eq!(
            decode_evs(&zero),
            Err(SidecarDecodeError::Damaged("bad_version"))
        );
        let mut letter = bytes.clone();
        letter[8] = b'x';
        assert_eq!(
            decode_evs(&letter),
            Err(SidecarDecodeError::Damaged("bad_version"))
        );
        let mut no_nul = bytes.clone();
        no_nul[9] = b' ';
        assert_eq!(
            decode_evs(&no_nul),
            Err(SidecarDecodeError::Damaged("missing_nul"))
        );
        let mut newer = bytes;
        newer[8] = b'4';
        assert_eq!(decode_evs(&newer), Err(SidecarDecodeError::NewerFormat(4)));
    }

    #[test]
    fn evs_v2_carries_queued_bans_and_v1_stays_v1() {
        let body = EvsBodyV1 {
            rebuilt_from: Vec::new(),
            rows: vec![sample_row()],
        };
        let none = encode_evs_with_queued_bans(&body, &[]).expect("encode");
        assert_eq!(&none[..10], EVS_HEADER_V1);
        assert_eq!(
            decode_evs_with_queued_bans(&none).expect("decode"),
            (body.clone(), Vec::new())
        );
        let bans = vec![QueuedBanV1 {
            stable_group_id: "g".into(),
            target: [5; 32],
            queued_at_unix_ms: 42,
        }];
        let some = encode_evs_with_queued_bans(&body, &bans).expect("encode");
        assert_eq!(&some[..10], EVS_HEADER_V2);
        assert_eq!(
            decode_evs_with_queued_bans(&some).expect("decode"),
            (body.clone(), bans)
        );
        assert_eq!(decode_evs(&some).expect("decode rows"), body);
        let mut trailing = some;
        trailing.push(0);
        assert_eq!(
            decode_evs_with_queued_bans(&trailing),
            Err(SidecarDecodeError::Damaged("trailing_bytes"))
        );
    }

    #[test]
    fn evjournal_round_trips_with_its_own_header() {
        let journal = EvJournalV1 {
            txid: [9; 16],
            stable_group_id: "g".into(),
            target: [3; 32],
            parent_head: "head".into(),
            next_revision: 5,
            result_epoch: Some(2),
            evidence: vec![[4; 32]],
            outgoing_event: vec![1, 2, 3],
            result_head: Some("head".to_string()),
        };
        let bytes = encode_evjournal(&journal).expect("encode");
        assert_eq!(&bytes[..8], EVJOURNAL_HEADER_V1);
        assert_eq!(decode_evjournal(&bytes).expect("decode"), journal);
        assert_eq!(
            decode_evjournal(&bytes[..7]),
            Err(SidecarDecodeError::Damaged("truncated_header"))
        );
        // A `.evs` file is not a journal.
        let evs = encode_evs(&EvsBodyV1::default()).expect("encode");
        assert_eq!(
            decode_evjournal(&evs),
            Err(SidecarDecodeError::Damaged("missing_prefix"))
        );
        let mut no_nul = bytes.clone();
        no_nul[7] = b'x';
        assert_eq!(
            decode_evjournal(&no_nul),
            Err(SidecarDecodeError::Damaged("missing_nul"))
        );
        let mut newer = bytes;
        newer[6] = b'2';
        assert_eq!(
            decode_evjournal(&newer),
            Err(SidecarDecodeError::NewerFormat(2))
        );
    }

    fn ctx<'a>(
        local: u8,
        admins: &'a [[u8; 32]],
        revoked: &'a BTreeSet<[u8; 32]>,
        elapsed: Duration,
    ) -> RowContext<'a> {
        RowContext {
            local: id(local),
            active_admins: admins,
            revoked_admins: revoked,
            quarantined: false,
            target_seated: true,
            elapsed,
            head_synced: true,
            durable: true,
            now_unix: 1_000,
            local_certificate_expired: false,
        }
    }

    #[test]
    fn evaluate_row_designated_commits_and_rank_waits_naming_designated() {
        let timing = S4Timing::default();
        let row = sample_row();
        let admins = [id(1), id(2), id(3)];
        let none = BTreeSet::new();
        let designated = evaluate_row(&row, &ctx(1, &admins, &none, Duration::ZERO), &timing);
        assert_eq!(designated.action, RowAction::CommitRemoval { rank: 0 });
        assert_eq!(designated.waiting, None);

        let early = evaluate_row(
            &row,
            &ctx(2, &admins, &none, Duration::from_secs(1)),
            &timing,
        );
        assert_eq!(early.action, RowAction::None);
        let waiting = early.waiting.expect("typed wait");
        assert_eq!(waiting.cause, WaitingCause::WaitingForDesignatedAdmin);
        assert_eq!(waiting.named, vec![id(1)]);
        assert_eq!(waiting.designated_detail, Some(DesignatedWaitDetail::Rank));
        assert!(waiting.remaining_ms.is_some());

        let fallback = evaluate_row(
            &row,
            &ctx(2, &admins, &none, timing.designated_window),
            &timing,
        );
        assert_eq!(fallback.action, RowAction::CommitRemoval { rank: 1 });
        let rank_two = evaluate_row(
            &row,
            &ctx(3, &admins, &none, timing.designated_window),
            &timing,
        );
        assert_eq!(rank_two.action, RowAction::None);

        // A non-admin observer sees the designated admin named.
        let observer = evaluate_row(&row, &ctx(8, &admins, &none, Duration::ZERO), &timing);
        assert_eq!(
            observer.waiting.map(|w| (w.cause, w.named)),
            Some((WaitingCause::WaitingForDesignatedAdmin, vec![id(1)]))
        );
    }

    #[test]
    fn evaluate_row_splits_unresolved_designated_admin() {
        // §2 (L170–L171, ruled 4 Nov 2026): a waiting rank splits the
        // designated wait on this node's recorded outbound hand-off
        // outcome against the designated admin itself, not on receipts
        // from other admins: an attempt that
        // completed with no exchange and no definitive failure is an
        // unresolved designated route while the budget is inside W
        // (rank 1 and two-admin groups included), and the rank keeps
        // its fallback time. A reached exchange, a definitive failure,
        // a record naming another admin (a designation change), a
        // record with no dispatched attempt (a reopened row) and no
        // record at all each keep the plain designated wait, and the
        // label stops at W (L171: "through W, not forever").
        let timing = S4Timing::default();
        let mut row = sample_row();
        let admins = [id(1), id(2), id(3)];
        let none = BTreeSet::new();
        // Rank 2 (id 3) waits past W; its fallback time is W + Δ. Rank 1
        // (id 2) waits through W and falls back at it.
        let during_window = Duration::from_secs(5);
        let unresolved = |designated: [u8; 32]| DesignatedHandoffRecord {
            designated,
            outcome: DesignatedHandoffOutcome::Unresolved,
        };

        // The s4_fallback_rank_manual shape: rank 1's hand-off receipt
        // is held (any-admin receipt), the budget is inside W, and this
        // node's own dispatch against the designated admin completed
        // without an exchange. The receipt and the budget no longer
        // decide; the record does.
        row.first_dispatch_unix_ms = Some(981_000);
        row.earliest_handoff_receipt_unix_ms = Some(999_000);
        row.designated_handoff = Some(unresolved(id(1)));
        let split = evaluate_row(&row, &ctx(3, &admins, &none, during_window), &timing);
        assert_eq!(split.action, RowAction::None);
        assert_eq!(
            split.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::UnresolvedDesignatedAdmin)
        );
        assert_eq!(
            split.waiting.as_ref().map(|waiting| waiting.named.clone()),
            Some(vec![id(1)])
        );
        assert!(split
            .waiting
            .as_ref()
            .is_some_and(|waiting| waiting.remaining_ms.is_some()));
        assert_eq!(
            split
                .waiting
                .as_ref()
                .and_then(|waiting| waiting.designated_detail),
            Some(DesignatedWaitDetail::Rank)
        );

        // The split shows from the start of the wait, not only past W:
        // L171 reads with the 4 Nov 2026 ruling (during W).
        let at_observation = evaluate_row(&row, &ctx(3, &admins, &none, Duration::ZERO), &timing);
        assert_eq!(
            at_observation.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::UnresolvedDesignatedAdmin)
        );

        // A record without a dispatched attempt never shows the label:
        // a reopened row dropped the superseded attempt's record with
        // its first-dispatch time, so the fresh wait stays plain until
        // the new attempt completes (r7 blocking finding 1).
        row.designated_handoff = Some(unresolved(id(1)));
        row.first_dispatch_unix_ms = None;
        let undispatched = evaluate_row(&row, &ctx(3, &admins, &none, during_window), &timing);
        assert_eq!(
            undispatched.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );
        row.first_dispatch_unix_ms = Some(981_000);

        // L171: the label "preserves priority through W, not forever".
        // Rank 2's fallback is W + Δ, so it still waits past W; from W
        // on its plain designated wait names the stagger, never an
        // unresolved route (r7 finding 5).
        let past_window = evaluate_row(
            &row,
            &ctx(
                3,
                &admins,
                &none,
                timing.designated_window + Duration::from_secs(2),
            ),
            &timing,
        );
        assert_eq!(
            past_window.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );
        // The boundary itself: 1 ms before W still shows the cause, and
        // the budget at exactly W is past the window (L171).
        let boundary = |elapsed| {
            evaluate_row(&row, &ctx(3, &admins, &none, elapsed), &timing)
                .waiting
                .map(|waiting| waiting.cause)
        };
        assert_eq!(
            boundary(timing.designated_window - Duration::from_millis(1)),
            Some(WaitingCause::UnresolvedDesignatedAdmin)
        );
        assert_eq!(
            boundary(timing.designated_window),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );

        // A reached exchange keeps the plain wait (a designated admin
        // this node reached is never unresolved).
        row.designated_handoff = Some(DesignatedHandoffRecord {
            designated: id(1),
            outcome: DesignatedHandoffOutcome::ExchangeReached,
        });
        let exchanged = evaluate_row(&row, &ctx(3, &admins, &none, during_window), &timing);
        assert_eq!(
            exchanged.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );

        // A definitive policy refusal keeps the plain wait (L171;
        // Engineer ruling, 4 Nov 2026 18:15 GMT).
        row.designated_handoff = Some(DesignatedHandoffRecord {
            designated: id(1),
            outcome: DesignatedHandoffOutcome::PolicyRefused,
        });
        let refused = evaluate_row(&row, &ctx(3, &admins, &none, during_window), &timing);
        assert_eq!(
            refused.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );

        // A definitive failure is §4's, never an unresolved route.
        row.designated_handoff = Some(DesignatedHandoffRecord {
            designated: id(1),
            outcome: DesignatedHandoffOutcome::Unsupported,
        });
        let unsupported = evaluate_row(&row, &ctx(3, &admins, &none, during_window), &timing);
        assert_eq!(
            unsupported.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );

        // A record naming another admin is void: a designation change
        // gets its own attempt.
        row.designated_handoff = Some(unresolved(id(2)));
        let redesignated = evaluate_row(&row, &ctx(3, &admins, &none, during_window), &timing);
        assert_eq!(
            redesignated.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );

        // No record keeps the plain wait, whatever the stand-in fields
        // say: the late-admin shape (first dispatch with the budget
        // already past W) and an attempt still in flight never show the
        // unresolved route on their own.
        row.designated_handoff = None;
        row.earliest_handoff_receipt_unix_ms = None;
        let unrecorded = evaluate_row(
            &row,
            &ctx(
                3,
                &admins,
                &none,
                timing.designated_window + Duration::from_secs(2),
            ),
            &timing,
        );
        assert_eq!(
            unrecorded.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::WaitingForDesignatedAdmin)
        );

        // Rank 1 shows the split during W (two-admin groups included:
        // its only peer is the designated admin) ...
        row.designated_handoff = Some(unresolved(id(1)));
        let rank_one_waits = evaluate_row(&row, &ctx(2, &admins, &none, during_window), &timing);
        assert_eq!(
            rank_one_waits.waiting.as_ref().map(|waiting| waiting.cause),
            Some(WaitingCause::UnresolvedDesignatedAdmin)
        );
        // ... and rank 1 falls back at W, so it never waits past W.
        let rank_one_fallback = evaluate_row(
            &row,
            &ctx(
                2,
                &admins,
                &none,
                timing.designated_window + Duration::from_secs(2),
            ),
            &timing,
        );
        assert_eq!(rank_one_fallback.waiting, None);
        assert_eq!(
            rank_one_fallback.action,
            RowAction::CommitRemoval { rank: 1 }
        );
    }

    #[test]
    fn evs_v3_persists_designated_handoff_outcomes() {
        // §5 v3: a row's designated hand-off record persists only in the
        // v3 extension, so an old-header row loads with the default and
        // a v3 file round-trips the record onto its row.
        let mut row = sample_row();
        let record = DesignatedHandoffRecord {
            designated: id(1),
            outcome: DesignatedHandoffOutcome::Unresolved,
        };
        row.designated_handoff = Some(record);
        let body = EvsBodyV1 {
            rebuilt_from: Vec::new(),
            rows: vec![row],
        };
        let handoffs = vec![DesignatedHandoffV3 {
            stable_group_id: body.rows[0].stable_group_id.clone(),
            target: body.rows[0].target,
            record,
        }];

        // With no outcome the file stays v1; with a queued ban only it
        // stays v2; with an outcome it is v3.
        let v1 = encode_evs_with_extensions(&body, &[], &[]).expect("encode v1");
        assert_eq!(&v1[..10], EVS_HEADER_V1);
        let ban = QueuedBanV1 {
            stable_group_id: body.rows[0].stable_group_id.clone(),
            target: body.rows[0].target,
            queued_at_unix_ms: 1,
        };
        let v2 =
            encode_evs_with_extensions(&body, std::slice::from_ref(&ban), &[]).expect("encode v2");
        assert_eq!(&v2[..10], EVS_HEADER_V2);
        let v3 = encode_evs_with_extensions(&body, &[ban], &handoffs).expect("encode v3");
        assert_eq!(&v3[..10], EVS_HEADER_V3);

        // The v1 and v2 files carry no record (the v1 body is frozen),
        // so those rows load with the default.
        for (name, bytes) in [("v1", v1), ("v2", v2)] {
            let (loaded, _) = decode_evs_with_queued_bans(&bytes).expect("decode");
            assert_eq!(
                loaded.rows[0].designated_handoff, None,
                "an old-header {name} row loads with the default"
            );
        }

        // The v3 file carries the queued ban and the record, applied
        // onto its row by key.
        let (loaded, bans) = decode_evs_with_queued_bans(&v3).expect("decode v3");
        assert_eq!(loaded.rows[0].designated_handoff, Some(record));
        assert_eq!(bans.len(), 1);

        // An entry whose row is absent is dropped, not an error.
        let orphan = encode_evs_with_extensions(
            &EvsBodyV1::default(),
            &[],
            &[DesignatedHandoffV3 {
                stable_group_id: "gone".into(),
                target: id(9),
                record,
            }],
        )
        .expect("encode orphan");
        let (loaded, _) = decode_evs_with_queued_bans(&orphan).expect("decode orphan");
        assert!(loaded.rows.is_empty());

        // Version 4 is a newer format, and a damaged v3 body is damaged.
        let mut newer = v3.clone();
        newer[8] = b'4';
        assert_eq!(
            decode_evs_with_queued_bans(&newer),
            Err(SidecarDecodeError::NewerFormat(4))
        );
        let mut trailing = v3.clone();
        trailing.push(0);
        assert_eq!(
            decode_evs_with_queued_bans(&trailing),
            Err(SidecarDecodeError::Damaged("trailing_bytes"))
        );
    }

    /// #1581 review r7: the record belongs to one attempt of one row.
    /// A completed row's work is over, so completion drops the record
    /// (Engineer ruling, 4 Nov 08:25 GMT), and a reopen starts a fresh
    /// attempt, so the superseded attempt's record leaves with its
    /// first-dispatch time — no result of an old attempt can label the
    /// new one (blocking finding 1).
    #[test]
    fn completion_and_reopen_clear_the_designated_handoff_record() {
        let record = DesignatedHandoffRecord {
            designated: id(1),
            outcome: DesignatedHandoffOutcome::Unresolved,
        };
        let mut store = ObligationStore::new();
        let k = key(9);
        store.intake(&k, revocation(1), Some("seat-a"), 1, [0; 16]);
        {
            let row = store.get_mut(&k).expect("row");
            row.first_dispatch_unix_ms = Some(9_000);
            row.designated_handoff = Some(record);
        }
        // Completion ends the work: the record does not survive it.
        assert!(store.complete(&k, Some("head".into()), Some(4), 2));
        assert_eq!(store.get(&k).expect("row").designated_handoff, None);

        // A row persisted by an earlier build may still hold a record
        // once loaded; a new-incarnation trigger reopens the row, and
        // the fresh attempt starts with no record and no dispatch time.
        {
            let row = store.get_mut(&k).expect("row");
            row.first_dispatch_unix_ms = Some(19_000);
            row.designated_handoff = Some(record);
        }
        assert_eq!(
            store.intake(&k, revocation(2), Some("seat-b"), 20, [0; 16]),
            IntakeOutcome::Reopened
        );
        let row = store.get(&k).expect("row");
        assert_eq!(row.first_dispatch_unix_ms, None);
        assert_eq!(row.designated_handoff, None);

        // A termination closes the row like a completion does, so it
        // drops the record as well.
        store.get_mut(&k).expect("row").designated_handoff = Some(record);
        assert!(store.terminate(&k, TerminationCause::GroupDeleted));
        assert_eq!(store.get(&k).expect("row").designated_handoff, None);
    }

    /// #1581 (Engineer ruling, 4 Nov 2026 17:22 GMT): the record ends
    /// at W and when the designated admin is no longer the one it
    /// names; only an outcome-bearing record changes the stored file.
    #[test]
    fn the_handoff_record_retires_at_w_and_on_a_designation_change() {
        let mut store = ObligationStore::new();
        let k = key(9);
        store.intake(&k, revocation(1), Some("seat-a"), 1, [0; 16]);
        let row = store.get_mut(&k).expect("row");
        let record = |outcome| DesignatedHandoffRecord {
            designated: id(1),
            outcome,
        };
        // Inside W, same admin, or no designation known: kept.
        row.designated_handoff = Some(record(DesignatedHandoffOutcome::Unresolved));
        assert!(!row.retire_designated_handoff(Some(id(1)), false));
        assert!(!row.retire_designated_handoff(None, false));
        assert!(row.designated_handoff.is_some());
        // At W: dropped, and the stored file changes.
        assert!(row.retire_designated_handoff(Some(id(1)), true));
        assert_eq!(row.designated_handoff, None);
        // Another designated admin: dropped.
        row.designated_handoff = Some(record(DesignatedHandoffOutcome::Unsupported));
        assert!(row.retire_designated_handoff(Some(id(2)), false));
        assert_eq!(row.designated_handoff, None);
        // A memory-only outcome is dropped too, but no file changes.
        row.designated_handoff = Some(record(DesignatedHandoffOutcome::ExchangeReached));
        assert!(!row.retire_designated_handoff(Some(id(1)), true));
        assert_eq!(row.designated_handoff, None);
        row.designated_handoff = Some(record(DesignatedHandoffOutcome::PolicyRefused));
        assert!(!row.retire_designated_handoff(Some(id(2)), false));
        assert_eq!(row.designated_handoff, None);
    }

    #[test]
    fn evaluate_row_typed_blocks() {
        let timing = S4Timing::default();
        let row = sample_row();
        let admins = [id(1)];
        let none = BTreeSet::new();
        let mut unsynced = ctx(1, &admins, &none, Duration::ZERO);
        unsynced.head_synced = false;
        assert_eq!(
            evaluate_row(&row, &unsynced, &timing)
                .waiting
                .map(|w| w.cause),
            Some(WaitingCause::WaitingForHeadSync)
        );
        let mut not_durable = ctx(1, &admins, &none, Duration::ZERO);
        not_durable.durable = false;
        assert_eq!(
            evaluate_row(&row, &not_durable, &timing)
                .waiting
                .map(|w| w.cause),
            Some(WaitingCause::WaitingForDurableIntake)
        );
        let mut forked = ctx(1, &admins, &none, Duration::ZERO);
        forked.quarantined = true;
        assert_eq!(
            evaluate_row(&row, &forked, &timing)
                .waiting
                .map(|w| w.cause),
            Some(WaitingCause::WaitingForForkResolution)
        );
        let revoked: BTreeSet<[u8; 32]> = [id(1)].into_iter().collect();
        let all_revoked = evaluate_row(&row, &ctx(5, &admins, &revoked, Duration::ZERO), &timing);
        assert_eq!(
            all_revoked.waiting.map(|w| (w.cause, w.named)),
            Some((WaitingCause::WaitingForEligibleAdminRevocation, vec![id(1)]))
        );
        assert_eq!(
            evaluate_row(&row, &ctx(5, &[], &none, Duration::ZERO), &timing)
                .waiting
                .map(|w| w.cause),
            Some(WaitingCause::WaitingForActiveAdmin)
        );
        let mut expired_self = ctx(1, &admins, &none, Duration::ZERO);
        expired_self.local_certificate_expired = true;
        assert_eq!(
            evaluate_row(&row, &expired_self, &timing)
                .waiting
                .map(|w| w.cause),
            Some(WaitingCause::LocalCommitterIneligible)
        );
        let mut left = ctx(1, &admins, &none, Duration::ZERO);
        left.target_seated = false;
        assert_eq!(
            evaluate_row(&row, &left, &timing).action,
            RowAction::SelfLeaveRekey { rank: 0 }
        );
    }

    #[test]
    fn evaluate_row_expiry_rechecks_raw_not_after() {
        let timing = S4Timing::default();
        let mut store = ObligationStore::new();
        store.intake(
            &key(4),
            EvictionTrigger::CertificateExpiry {
                certificate_digest: "d".into(),
                not_after: 2_000,
            },
            None,
            0,
            [0; 16],
        );
        let row = store.get(&key(4)).expect("row").clone();
        let admins = [id(1)];
        let none = BTreeSet::new();
        let early = evaluate_row(&row, &ctx(1, &admins, &none, Duration::ZERO), &timing);
        assert_eq!(
            early.waiting.map(|w| w.cause),
            Some(WaitingCause::WaitingForCertificateExpiry)
        );
        let mut later = ctx(1, &admins, &none, Duration::ZERO);
        later.now_unix = 2_001;
        assert_eq!(
            evaluate_row(&row, &later, &timing).action,
            RowAction::CommitRemoval { rank: 0 }
        );
    }

    #[test]
    fn handoff_round_trips_with_exact_consumption() {
        let handoff = EvictionHandoffV1 {
            stable_group_id: "g".into(),
            target: id(3),
            observed_parent_head: "head".into(),
            revocation_records: vec![vec![1, 2, 3]],
            self_leave_commit: None,
            expired_certificate: None,
            renewed_certificate: None,
        };
        let bytes = encode_handoff(&handoff).expect("encode");
        assert!(bytes.starts_with(EVICTION_HANDOFF_PREFIX));
        assert_eq!(decode_handoff(&bytes), Ok(handoff.clone()));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_handoff(&trailing),
            Err(HandoffDecodeError::Malformed)
        );
        assert_eq!(
            decode_handoff(b"X0XCE1..."),
            Err(HandoffDecodeError::WrongPrefix)
        );
        let empty = EvictionHandoffV1 {
            revocation_records: Vec::new(),
            ..handoff.clone()
        };
        assert_eq!(
            decode_handoff(&encode_handoff(&empty).expect("encode")),
            Err(HandoffDecodeError::OutOfBounds)
        );
        let crowded = EvictionHandoffV1 {
            revocation_records: vec![vec![0]; MAX_HANDOFF_REVOCATION_RECORDS + 1],
            ..handoff
        };
        assert_eq!(
            decode_handoff(&encode_handoff(&crowded).expect("encode")),
            Err(HandoffDecodeError::OutOfBounds)
        );
    }

    #[test]
    fn quarantine_names_round_trip() {
        let pending = quarantine_pending_name(EVS_FILE_NAME, &[7; 16], b"damaged");
        let (txid, h) =
            parse_quarantine_pending_name(EVS_FILE_NAME, &pending).expect("parse pending");
        assert_eq!(txid, [7; 16]);
        assert_eq!(h, quarantine_hash_hex(b"damaged"));
        assert_eq!(
            quarantine_history_name(&pending).map(|n| n.ends_with(&h)),
            Some(true)
        );
        assert!(parse_quarantine_pending_name(EVS_FILE_NAME, "other.q-00-11.pending").is_none());
    }

    /// ADR 0110 §4 (#1357 review P1): completion keeps a crypto-only
    /// exclusion frame as durable replay evidence in the `.evs` row, and
    /// drops any other saved event. The row survives an encode/decode
    /// round trip with the frame.
    #[test]
    fn completion_keeps_a_crypto_exclusion_frame_as_replay_evidence() {
        let mut store = ObligationStore::new();
        let frame_key = key(1);
        let other_key = key(2);
        let mut frame = crate::groups::crypto_exclusion::CRYPTO_EXCLUSION_PREFIX.to_vec();
        frame.extend_from_slice(b"frame");
        for (k, event) in [(&frame_key, frame.clone()), (&other_key, b"{}".to_vec())] {
            store.intake(k, revocation(1), None, 0, [0; 16]);
            store.get_mut(k).expect("row").outgoing_event = Some(event);
            assert!(store.complete(k, Some("r".into()), Some(2), 1));
        }
        assert_eq!(
            store
                .get(&frame_key)
                .expect("row")
                .outgoing_event
                .as_deref(),
            Some(frame.as_slice())
        );
        assert!(store.get(&other_key).expect("row").outgoing_event.is_none());
        let body = EvsBodyV1 {
            rebuilt_from: Vec::new(),
            rows: store.to_rows(),
        };
        let decoded = decode_evs(&encode_evs(&body).expect("encode")).expect("decode");
        let reloaded = ObligationStore::from_rows(decoded.rows);
        assert_eq!(
            reloaded
                .get(&frame_key)
                .expect("row")
                .outgoing_event
                .as_deref(),
            Some(frame.as_slice())
        );
    }

    /// Replay frames are bounded: only the newest
    /// [`MAX_REPLAY_FRAMES_PER_GROUP`] completed rows of a group keep theirs.
    #[test]
    fn retention_keeps_only_the_newest_replay_frames() {
        let mut store = ObligationStore::new();
        let mut frame = crate::groups::crypto_exclusion::CRYPTO_EXCLUSION_PREFIX.to_vec();
        frame.push(0);
        let total = MAX_REPLAY_FRAMES_PER_GROUP + 3;
        for n in 0..total {
            let k = key(u8::try_from(n + 1).expect("small"));
            store.intake(&k, revocation(1), None, 0, [0; 16]);
            store.get_mut(&k).expect("row").outgoing_event = Some(frame.clone());
            store.complete(&k, None, None, u64::try_from(n).expect("small") + 1);
        }
        assert!(store.apply_retention(100));
        let kept: Vec<u8> = (0..total)
            .filter(|n| {
                let k = key(u8::try_from(n + 1).expect("small"));
                store.get(&k).expect("row").outgoing_event.is_some()
            })
            .map(|n| u8::try_from(n).expect("small"))
            .collect();
        let expected: Vec<u8> = (3..u8::try_from(total).expect("small")).collect();
        assert_eq!(kept, expected, "the oldest rows drop their frames");
        assert!(!store.apply_retention(100), "retention is idempotent");
    }
}
