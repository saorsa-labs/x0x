//! ADR 0116 §4: the supported runtime trim.
//!
//! One retention service over the open store, its immutable startup policy
//! and its live pin source. It is reached through
//! [`super::HistoryHandle::retain`], `POST /history/retain` and
//! `x0x history retain`. A trim applies the configured policy; it is not a
//! purge, and it takes no SQL, path, force flag, replacement policy or scope
//! selector. Its work is bounded by a row budget and a time budget.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::HistoryError;

/// Default row budget of one trim (ADR 0116 §4).
pub const RETAIN_DEFAULT_MAX_ROWS: u32 = 4096;
/// Largest row budget a trim accepts.
pub const RETAIN_MAX_ROWS: u32 = 65_536;
/// Default time budget of one trim, in milliseconds.
pub const RETAIN_DEFAULT_BUDGET_MS: u32 = 2_000;
/// Largest time budget a trim accepts, in milliseconds.
pub const RETAIN_MAX_BUDGET_MS: u32 = 10_000;

/// The two knobs a trim accepts (ADR 0116 §4). Nothing else can be passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainOptions {
    /// Most rows this trim may delete, pin-ceiling deletions included
    /// (1–65 536; default 4 096).
    pub max_rows: u32,
    /// Work-admission budget in milliseconds (1–10 000; default 2 000).
    /// It is checked before each statement. One statement already in
    /// flight may run past it; it is not a hard response deadline.
    pub budget_ms: u32,
}

impl Default for RetainOptions {
    fn default() -> Self {
        Self {
            max_rows: RETAIN_DEFAULT_MAX_ROWS,
            budget_ms: RETAIN_DEFAULT_BUDGET_MS,
        }
    }
}

impl RetainOptions {
    /// Check both budgets are inside their allowed ranges.
    ///
    /// # Errors
    /// [`RetainError::InvalidOptions`] names the out-of-range field.
    pub fn validate(&self) -> Result<(), RetainError> {
        if !(1..=RETAIN_MAX_ROWS).contains(&self.max_rows) {
            return Err(RetainError::InvalidOptions(format!(
                "max_rows must be between 1 and {RETAIN_MAX_ROWS}, got {}",
                self.max_rows
            )));
        }
        if !(1..=RETAIN_MAX_BUDGET_MS).contains(&self.budget_ms) {
            return Err(RetainError::InvalidOptions(format!(
                "budget_ms must be between 1 and {RETAIN_MAX_BUDGET_MS}, got {}",
                self.budget_ms
            )));
        }
        Ok(())
    }
}

/// Where a trim ended (ADR 0116 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainState {
    /// This observed pass found no eligible policy work pending. It promises
    /// neither a smaller file nor a bound on future writes.
    Complete,
    /// Work remains: a budget ran out, the caller cancelled, or index
    /// reclamation is still pending.
    MoreWork,
    /// No eligible policy work remains, but pinned or exempt rows still keep
    /// a configured bound exceeded. Never returned while eligible work
    /// remains.
    BlockedByProtectedRows,
}

/// Why a trim stopped before finishing a full cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainStop {
    /// `max_rows` were deleted.
    RowBudget,
    /// `budget_ms` ran out before a statement could start.
    TimeBudget,
    /// The caller went away; the trim stopped at the next boundary.
    Cancelled,
    /// The full-text index had not settled within the budget, so the
    /// whole-database budget could not yet be measured (part 1's rule).
    Reclamation,
}

/// Committed deletions, by retention phase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainDeleted {
    /// The global age bound.
    pub global_age: u64,
    /// Class and topic-rule age bounds.
    pub rule_ages: u64,
    /// ADR 0068 pin ceilings (pinned groups shedding their own oldest rows).
    pub pin_ceilings: u64,
    /// Class byte budgets.
    pub class_budgets: u64,
    /// Topic-rule byte budgets.
    pub topic_budgets: u64,
    /// Exact-scope byte budgets.
    pub scope_budgets: u64,
    /// The whole-database budget.
    pub global_budget: u64,
}

impl RetainDeleted {
    /// All committed deletions.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.global_age
            + self.rule_ages
            + self.pin_ceilings
            + self.class_budgets
            + self.topic_budgets
            + self.scope_budgets
            + self.global_budget
    }
}

/// What one trim did (ADR 0116 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainReport {
    /// Where the trim ended.
    pub state: RetainState,
    /// Rows deleted in committed transactions.
    pub deleted: u64,
    /// The same, by phase.
    pub deleted_by_phase: RetainDeleted,
    /// Rows deleted by the ADR 0068 pin ceilings (also in `deleted`).
    pub pin_ceiling_deleted: u64,
    /// Wall-clock time the trim took, in milliseconds.
    pub elapsed_ms: u64,
    /// Why the trim stopped early, when it did.
    pub stopped_by: Option<RetainStop>,
}

impl RetainReport {
    pub(crate) fn new(
        state: RetainState,
        deleted: RetainDeleted,
        elapsed: std::time::Duration,
        stopped_by: Option<RetainStop>,
    ) -> Self {
        Self {
            state,
            deleted: deleted.total(),
            deleted_by_phase: deleted,
            pin_ceiling_deleted: deleted.pin_ceilings,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            stopped_by,
        }
    }
}

/// Why a trim was refused or failed.
#[derive(Debug)]
pub enum RetainError {
    /// A budget is out of range (HTTP 400).
    InvalidOptions(String),
    /// Another retention operation holds this store (HTTP 409
    /// `history_retention_busy`). Nothing was queued.
    Busy,
    /// SQLite failed. `committed` counts the batches committed before the
    /// failure; they are not rolled back (HTTP 500).
    Failed {
        /// The failure.
        error: HistoryError,
        /// Committed work before it.
        committed: RetainReport,
    },
}

impl std::fmt::Display for RetainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOptions(message) => write!(f, "{message}"),
            Self::Busy => write!(f, "another history retention operation is running"),
            Self::Failed { error, committed } => write!(
                f,
                "history trim failed after {} committed deletions: {error}",
                committed.deleted
            ),
        }
    }
}

impl std::error::Error for RetainError {}

/// Budgets handed to `Store::trim`.
pub(crate) struct TrimBudget<'a> {
    /// Most rows to delete.
    pub(crate) max_rows: u64,
    /// When the caller started the trim; `elapsed_ms` counts from here.
    pub(crate) started: std::time::Instant,
    /// No statement starts at or after this instant.
    pub(crate) deadline: std::time::Instant,
    /// Set when the caller goes away.
    pub(crate) cancel: &'a AtomicBool,
}

/// Sets the trim's cancel flag when the caller's future is dropped, so the
/// blocking trim stops at its next boundary.
pub(crate) struct CancelOnDrop(pub(crate) Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
