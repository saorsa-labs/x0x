//! Typed errors for the notes store (ADR 0081).
//!
//! Every error names the fail-closed outcome the REST layer maps it to; no
//! variant is ever produced by letting a loro panic escape.

/// Errors produced by the notes engine and store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoteError {
    /// A loro operation panicked (or its blocking task did). The doc was
    /// quarantined and the note rebuilt from its records (ADR 0081 §3).
    #[error("note {note_id}: engine fault during {op}")]
    EngineFault {
        /// The note whose doc faulted.
        note_id: String,
        /// The operation that faulted.
        op: &'static str,
    },
    /// The note faulted three times in a row and is degraded: reads return
    /// the last good text, writes are refused with 503 `note_engine_fault`.
    #[error("note {note_id} is degraded after repeated engine faults")]
    Degraded {
        /// The degraded note.
        note_id: String,
    },
    /// `base_version` names ops this replica does not hold: 409
    /// `base_version_unknown` (never merge against a partial base).
    #[error("base_version names operations this replica does not hold")]
    BaseVersionUnknown,
    /// `base_version` is known but is not the note's current version. The
    /// three-way merge path is a later slice, so this slice refuses: 409
    /// `base_version_stale`.
    #[error("base_version is not the note's current version; re-read and retry")]
    BaseVersionStale,
    /// The version token is not valid base64url `Frontiers`.
    #[error("invalid version token: {0}")]
    InvalidVersion(String),
    /// The write would take the note past its 4 MiB cap: 413 `note_too_large`.
    #[error("note would grow to {attempted} bytes of records, over the {cap}-byte note cap")]
    NoteTooLarge {
        /// Record bytes the note already holds.
        current: u64,
        /// Record bytes the note would hold after the write.
        attempted: u64,
        /// The per-note cap.
        cap: u64,
    },
    /// The write would take the store past its 12 MiB budget: 413
    /// `notes_store_full`.
    #[error("notes store would grow past its budget ({current} of {budget} bytes used)")]
    StoreFull {
        /// Current encoded retained-image bytes.
        current: u64,
        /// Projected bytes after the write.
        projected: u64,
        /// The store budget.
        budget: u64,
    },
    /// No note with this id exists in the store.
    #[error("note not found")]
    NotFound,
    /// A request field was invalid.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// A record key for this author and seq already exists (write-once).
    #[error("record key {0} already exists; retry the save")]
    SeqConflict(String),
    /// No unused peer id could be drawn (only reachable with an injected RNG).
    #[error("could not draw an unused loro peer id")]
    PeerIdExhausted,
    /// Signing a record failed.
    #[error("record signing failed: {0}")]
    Signing(String),
    /// The underlying KV store failed.
    #[error("notes store error: {0}")]
    Store(String),
    /// The caller is not permitted to write this store.
    #[error("not permitted: {0}")]
    Forbidden(String),
    /// A save above 256 KiB changes so much in one place that no edit
    /// script within the diff budgets keeps the unchanged text's identity:
    /// 422 `note_edit_too_large_to_merge_safely`. Accepting it could bring
    /// back text another member deleted concurrently (#1029), so it is
    /// refused and nothing is written.
    #[error(
        "this save turns {old_lines} lines into {new_lines} in one place, too much to merge \
         safely with concurrent edits; save the change in smaller steps"
    )]
    EditTooLargeToMergeSafely {
        /// Old lines in the region that could not be aligned.
        old_lines: usize,
        /// New lines in that region.
        new_lines: usize,
    },
}

impl NoteError {
    /// Stable machine-readable reason, used as the REST `error` field.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::EngineFault { .. } | Self::Degraded { .. } => "note_engine_fault",
            Self::BaseVersionUnknown => "base_version_unknown",
            Self::BaseVersionStale => "base_version_stale",
            Self::InvalidVersion(_) => "invalid_version",
            Self::NoteTooLarge { .. } => "note_too_large",
            Self::StoreFull { .. } => "notes_store_full",
            Self::NotFound => "note_not_found",
            Self::InvalidRequest(_) => "invalid_request",
            Self::SeqConflict(_) => "record_seq_conflict",
            Self::PeerIdExhausted => "peer_id_exhausted",
            Self::Signing(_) => "record_signing_failed",
            Self::Store(_) => "notes_store_error",
            Self::Forbidden(_) => "forbidden",
            Self::EditTooLargeToMergeSafely { .. } => "note_edit_too_large_to_merge_safely",
        }
    }
}
