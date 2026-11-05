//! #1809: files that hold group shared secrets are owner-only (0600).
//!
//! `write_named_groups_json_atomic` writes `named_groups.json`, the
//! Home-suite sidecar and the other group sidecars. Each test asserts the
//! Unix file mode after a real save or load.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::os::unix::fs::PermissionsExt;

fn mode_of(path: &FsPath) -> u32 {
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

fn seed_world_readable(path: &FsPath, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("seed");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("seed 0644");
    assert_eq!(mode_of(path), 0o644, "seed mode");
}

/// A new file is created 0600.
#[tokio::test]
async fn new_named_groups_json_is_owner_only() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("named_groups.json");

    let outcome = write_named_groups_json_atomic(&path, "{}")
        .await
        .expect("no io err");
    assert_eq!(outcome, AtomicWriteOutcome::Durable);
    assert_eq!(mode_of(&path), 0o600, "new named_groups.json mode");
}

/// An older 0644 file is 0600 after the next save.
#[tokio::test]
async fn save_tightens_existing_named_groups_json() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("named_groups.json");
    seed_world_readable(&path, b"{}");

    let outcome = write_named_groups_json_atomic(&path, "{}")
        .await
        .expect("no io err");
    assert_eq!(outcome, AtomicWriteOutcome::Durable);
    assert_eq!(mode_of(&path), 0o600, "saved named_groups.json mode");
}

/// The daemon's startup load tightens an older 0644 `named_groups.json`
/// and Home-suite sidecar before any save happens.
#[tokio::test]
async fn load_tightens_existing_group_files() {
    let dir = tempfile::tempdir().expect("tmp");
    let named = dir.path().join("named_groups.json");
    let sidecar = dir.path().join("home_suite_groups.json");
    seed_world_readable(&named, b"{}");
    seed_world_readable(&sidecar, b"{}");

    let groups = load_named_groups_merged(&named, &sidecar)
        .await
        .expect("load");
    assert!(groups.is_empty());
    assert_eq!(mode_of(&named), 0o600, "loaded named_groups.json mode");
    assert_eq!(mode_of(&sidecar), 0o600, "loaded sidecar mode");
}
