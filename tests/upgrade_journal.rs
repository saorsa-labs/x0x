#![allow(clippy::unwrap_used, clippy::expect_used)]

//! M2 S2a record regressions. These tests only read and write isolated files;
//! they never start a daemon, bind a socket, or contact the network.

use std::collections::BTreeMap;
use std::path::Path;

use tempfile::TempDir;
use x0x::upgrade::restart::{RestartMode, UpgradeHandoff, HANDOFF_FILE_NAME};

fn legacy_handoff(root: &Path, to_version: &str) -> UpgradeHandoff {
    UpgradeHandoff {
        from_version: "0.48.1".to_owned(),
        to_version: to_version.to_owned(),
        target_path: root.join("x0xd"),
        backup_path: root.join("x0xd.backup"),
        argv: vec!["x0xd".to_owned(), "--name".to_owned(), "alice".to_owned()],
        cwd: root.to_string_lossy().into_owned(),
        env: BTreeMap::from([("RUST_LOG".to_owned(), "info".to_owned())]),
        old_pid: 1234,
        api_addr: "127.0.0.1:12700".parse().unwrap(),
        started_at: 1_792_500_000,
        mode: RestartMode::TransactionalHandoff,
        launchd_verified: None,
        systemd_verified: None,
    }
}

#[test]
fn handoff_replacement_does_not_modify_previous_record_inode() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let retained_path = dir.path().join("retained-handoff.json");
    legacy_handoff(dir.path(), "0.48.2").write(&path).unwrap();
    let previous = std::fs::read(&path).unwrap();
    std::fs::hard_link(&path, &retained_path).unwrap();

    legacy_handoff(dir.path(), "0.48.3").write(&path).unwrap();

    // ADR 0094 requires a replacement record followed by rename. In-place
    // truncation changes the previous inode and can destroy its valid record
    // before the new bytes reach the record barrier.
    assert_eq!(
        std::fs::read(&retained_path).unwrap(),
        previous,
        "writing a replacement must leave the prior record inode intact"
    );
    assert_eq!(UpgradeHandoff::read(&path).unwrap().to_version, "0.48.3");
}

#[test]
fn handoff_writer_retains_legacy_diagnostic_fields_and_referenced_files() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let handoff = legacy_handoff(dir.path(), "0.48.2");
    std::fs::write(&handoff.target_path, b"configured binary").unwrap();
    std::fs::write(&handoff.backup_path, b"rollback binary").unwrap();
    handoff.write(&path).unwrap();

    let encoded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let legacy = serde_json::to_value(&handoff).unwrap();
    for (name, expected) in legacy.as_object().unwrap() {
        assert_eq!(&encoded[name], expected, "legacy field {name} was lost");
    }
    let parsed = UpgradeHandoff::read(&path).unwrap();
    assert_eq!(parsed.argv, handoff.argv);
    assert_eq!(parsed.env, handoff.env);
    assert_eq!(
        std::fs::read(&handoff.target_path).unwrap(),
        b"configured binary"
    );
    assert_eq!(
        std::fs::read(&handoff.backup_path).unwrap(),
        b"rollback binary"
    );
}

#[test]
fn torn_legacy_handoff_read_preserves_diagnostic_bytes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let complete = serde_json::to_vec(&legacy_handoff(dir.path(), "0.48.2")).unwrap();
    let torn = &complete[..complete.len() / 2];
    std::fs::write(&path, torn).unwrap();

    assert!(UpgradeHandoff::read(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), torn);
}
