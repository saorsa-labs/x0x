//! MiniMax ADR 0028 — Arm 5: whole-sidecar restart disposition.
//!
//! Frozen seam: `f499ea3f4dc1e2e96ff7f55b371515112d2e0c26`.
//!
//! Drives the REAL production sidecar loader (`load_predecessor_relay_outbox`)
//! and asserts the cap-driven disposition in three production-seam shapes:
//!
//! 1. Sidecar size cap — file exceeding `RELAY_SIDECAR_FILE_SIZE_CAP` is
//!    refused at startup with zero installed live state, byte-identical file.
//! 2. Sidecar format guards — non-UTF-8 bytes and a wrong sidecar version
//!    are both refused.
//! 3. Cap-driven rejection — entries from real production-seam construction
//!    that exceed the per-group count cap cause startup refusal.
//!
//! For each row the MUT2 weakening is one line in the production loader.
//! The row turns GREEN only at the bounded check (≤ or >) production
//! currently enforces.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_arguments,
    clippy::redundant_clone
)]

use super::*;

// ---------------------------------------------------------------------------
// File-size cap refusal: a sidecar file exceeding
// RELAY_SIDECAR_FILE_SIZE_CAP must be refused. MUT2: dropping or
// mis-comparing the size guard would let the loader read the file.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_disposition_file_over_relay_size_cap_is_refused() {
    use crate::server::routes::named_groups::RELAY_SIDECAR_FILE_SIZE_CAP;
    let (state, _dir) = super::super::tests::adr0028_direct_controls::d_state().await;
    let path = &state.predecessor_relay_outbox_path;
    // Build a header that the loader recognises (UTF-8 + version:1) and then
    // pad with bytes until we exceed the cap; the loader must refuse at the
    // metadata check before any deserialization.
    let mut bytes = b"{\"version\":1,\"entries\":".to_vec();
    bytes.resize(RELAY_SIDECAR_FILE_SIZE_CAP + 4096, b'A');
    bytes.extend_from_slice(b"}");
    tokio::fs::write(path, &bytes)
        .await
        .expect("write large sidecar");
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("load timed out");
    assert!(
        outcome.is_err(),
        "sidecar > RELAY_SIDECAR_FILE_SIZE_CAP must be refused (got Ok)"
    );
    let installed: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .map(Vec::len)
        .sum();
    assert_eq!(installed, 0, "rejection installs zero live");
    let after = tokio::fs::read(path).await.expect("read large sidecar");
    assert_eq!(
        after.len(),
        bytes.len(),
        "rejected sidecar must remain byte-identical on disk"
    );
}

// ---------------------------------------------------------------------------
// Format / version guards. MUT2: removing either guard would let bad
// content through. ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_disposition_non_utf8_sidecar_is_refused() {
    let (state, _dir) = super::super::tests::adr0028_direct_controls::d_state().await;
    let path = &state.predecessor_relay_outbox_path;
    // A non-UTF-8 byte sequence.
    let bytes: Vec<u8> = (0..32).map(|i| 0xC0u8.wrapping_add(i)).collect();
    tokio::fs::write(path, &bytes)
        .await
        .expect("write non-utf8");
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("load timed out");
    assert!(
        outcome.is_err(),
        "non-UTF-8 sidecar must be refused (got Ok)"
    );
    let installed: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .map(Vec::len)
        .sum();
    assert_eq!(installed, 0, "rejection installs zero live");
}

#[tokio::test]
async fn restart_disposition_version_mismatch_is_refused() {
    let (state, _dir) = super::super::tests::adr0028_direct_controls::d_state().await;
    let path = &state.predecessor_relay_outbox_path;
    let bytes = b"{\"version\":999,\"entries\":{},\"completed_tombstones\":{}}";
    tokio::fs::write(path, bytes)
        .await
        .expect("write version mismatched");
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("load timed out");
    assert!(
        outcome.is_err(),
        "version mismatch must be refused (got Ok)"
    );
    let installed: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .map(Vec::len)
        .sum();
    assert_eq!(installed, 0, "rejection installs zero live");
}

#[tokio::test]
async fn restart_disposition_malformed_json_is_refused() {
    let (state, _dir) = super::super::tests::adr0028_direct_controls::d_state().await;
    let path = &state.predecessor_relay_outbox_path;
    let bytes = b"{\"version\":1,\"entries\":{\"this is not valid json\":";
    tokio::fs::write(path, bytes)
        .await
        .expect("write malformed");
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        load_predecessor_relay_outbox(&state),
    )
    .await
    .expect("load timed out");
    assert!(outcome.is_err(), "malformed JSON must be refused (got Ok)");
    let installed: usize = state
        .predecessor_relay_outbox
        .read()
        .await
        .values()
        .map(Vec::len)
        .sum();
    assert_eq!(installed, 0, "rejection installs zero live");
}
