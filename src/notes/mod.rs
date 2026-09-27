//! Collaborative notes (ADR 0081, superseding the CRDT choice of ADR 0075).
//!
//! A note is a loro doc with one text root, stored in the group's sealed
//! `notes` KV store as write-once, author-signed update records
//! (`n/<note_id>/u/<author_hex>/<seq>`) plus an LWW metadata value
//! (`n/<note_id>/meta`). The store is opened through the ordinary group-store
//! path, so it is sealed exactly like the Wiki store and #914 task lists.
//!
//! - `record`: `NoteUpdateRecordV2`, keys, signing and the receiver rule.
//! - `text_diff`: the character-exact edit script for saves above 256 KiB
//!   (#1029).
//! - `engine`: the loro doc per note, isolated with `spawn_blocking` and
//!   `catch_unwind`, poisoned-doc quarantine, peer-id allocation, versions.
//! - `store`: metadata, sync, save, the 4 MiB note cap and 12 MiB store
//!   budget.
//!
//! This slice covers create, read, list and save. The three-way merge from
//! an older `base_version`, the Wiki import, scratchpads and the GUI are
//! later slices; a save whose `base_version` is not current is refused with
//! 409 `base_version_stale`.

// ADR 0081 §3: panic containment relies on unwinding. A build with
// `panic = "abort"` would turn any loro import panic into a process abort,
// so it must not compile.
#[cfg(panic = "abort")]
compile_error!(
    "x0x notes (ADR 0081 §3) require panic = \"unwind\": loro import panics must be \
     caught and contained, which is impossible under panic = \"abort\""
);

pub mod engine;
pub mod error;
mod kv_handle;
pub mod record;
pub mod store;
mod text_diff;

pub use engine::{EngineCountersSnapshot, NoteView, NotesEngine};
pub use error::NoteError;
pub use record::NoteUpdateRecordV2;
pub use store::{
    NoteDocument, NoteKv, NoteSummary, NotesStore, SaveOutcome, NOTES_STORE_NAME, NOTE_CAP_BYTES,
    STORE_BUDGET_BYTES,
};

/// ADR 0081 §3 Validation: the release profile unwinds. The
/// `compile_error!` above stops any build compiled with `panic = "abort"`;
/// this test also fails if a `panic = "abort"` line is added to any profile
/// in the manifest, before a release build is ever attempted.
#[cfg(test)]
mod panic_strategy_tests {
    #[test]
    fn release_profile_keeps_panic_unwind() {
        const { assert!(cfg!(panic = "unwind"), "tests must run with panic = unwind") };
        let manifest = include_str!("../../Cargo.toml");
        let offending: Vec<&str> = manifest
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim())
            .filter(|line| {
                let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
                compact.starts_with("panic=") && compact.contains("abort")
            })
            .collect();
        assert!(
            offending.is_empty(),
            "Cargo.toml sets panic = \"abort\" ({offending:?}); ADR 0081 §3 requires unwind"
        );
    }
}

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod store_tests;
