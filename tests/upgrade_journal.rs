#![allow(clippy::unwrap_used, clippy::expect_used)]

//! M2 S2a record regressions. These tests only read and write isolated files;
//! they never start a daemon, bind a socket, or contact the network.

use std::collections::BTreeMap;
use std::path::Path;

use tempfile::TempDir;
use x0x::upgrade::restart::{
    resolve_restart_plan, LaunchdPolicyReadback, RestartMode, RestartOwnershipError,
    SupervisionSignals, SystemdPolicyReadback, UpgradeHandoff, HANDOFF_FILE_NAME,
};

// The records are crate-private until the S3 launcher consumes them. Include
// the same implementation here to exercise the durable writer's failure hook.
#[path = "../src/upgrade/journal.rs"]
mod journal;

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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
#[test]
fn handoff_writer_refuses_missing_parent_without_creating_directories() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("missing").join("data");
    let path = missing.join(HANDOFF_FILE_NAME);
    assert!(legacy_handoff(dir.path(), "0.48.2").write(&path).is_err());
    assert!(!dir.path().join("missing").exists());
}

#[test]
fn unmanaged_legacy_writer_preserves_released_shape_and_referenced_files() {
    let dir = TempDir::new().unwrap();
    let path = dir
        .path()
        .join("missing")
        .join("data")
        .join(HANDOFF_FILE_NAME);
    let mut handoff = legacy_handoff(dir.path(), "0.48.2");
    std::fs::write(&handoff.target_path, b"configured binary").unwrap();
    std::fs::write(&handoff.backup_path, b"rollback binary").unwrap();

    // Exercise the Windows compatibility writer through its private seam on
    // every CI platform. Its success is not an M2 directory-barrier receipt.
    for version in ["0.48.2", "0.48.3"] {
        handoff.to_version = version.to_owned();
        journal::write_legacy_handoff(&path, &handoff).unwrap();
        let encoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(encoded, serde_json::to_value(&handoff).unwrap());
        assert_eq!(UpgradeHandoff::read(&path).unwrap().to_version, version);
        assert_eq!(
            std::fs::read(&handoff.target_path).unwrap(),
            b"configured binary"
        );
        assert_eq!(
            std::fs::read(&handoff.backup_path).unwrap(),
            b"rollback binary"
        );
        assert_diagnostic_only(&journal::read_boot_records(path.parent().unwrap()));
    }
}

#[cfg(unix)]
#[test]
fn unmanaged_legacy_replacement_keeps_the_previous_record_inode() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let retained = dir.path().join("retained-handoff.json");
    journal::write_legacy_handoff(&path, &legacy_handoff(dir.path(), "0.48.2")).unwrap();
    let previous = std::fs::read(&path).unwrap();
    std::fs::hard_link(&path, &retained).unwrap();

    journal::write_legacy_handoff(&path, &legacy_handoff(dir.path(), "0.48.3")).unwrap();

    assert_eq!(std::fs::read(&retained).unwrap(), previous);
    assert_eq!(UpgradeHandoff::read(&path).unwrap().to_version, "0.48.3");
}

#[test]
fn unmanaged_legacy_writer_preserves_untrusted_and_m2_records() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let handoff = legacy_handoff(dir.path(), "0.48.2");
    std::fs::write(&handoff.target_path, b"configured binary").unwrap();
    std::fs::write(&handoff.backup_path, b"rollback binary").unwrap();
    let mut m2 = serde_json::to_value(&handoff).unwrap();
    m2["schema_version"] = serde_json::json!(1);
    m2["record_kind"] = serde_json::json!("handoff");
    m2["transaction_id"] = serde_json::json!("transaction-a");
    m2["generation"] = serde_json::json!(3);
    m2["instance_id"] = serde_json::json!("alice");
    for bytes in [
        br#"{"schema_version":"#.to_vec(),
        br#"{"schema_version":999}"#.to_vec(),
        serde_json::to_vec(&m2).unwrap(),
    ] {
        std::fs::write(&path, &bytes).unwrap();

        assert!(journal::write_legacy_handoff(&path, &handoff).is_err());

        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::read(&handoff.target_path).unwrap(),
            b"configured binary"
        );
        assert_eq!(
            std::fs::read(&handoff.backup_path).unwrap(),
            b"rollback binary"
        );
    }
}

#[test]
fn recovery_records_preserve_real_cleanup_candidates() {
    let dir = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let staged = dir.path().join(".x0x-upgrade-retained");
    let sidelined = dir.path().join("x0xd.x0xold-retained");
    std::fs::create_dir(&staged).unwrap();
    std::fs::write(staged.join("candidate"), b"candidate").unwrap();
    std::fs::write(&sidelined, b"rollback").unwrap();
    for name in [
        journal::JOURNAL_FILE_NAME,
        journal::HANDOFF_FILE_NAME,
        journal::BOOT_FILE_NAME,
    ] {
        let record = data.path().join(name);
        for bytes in [
            br#"{"schema_version":999}"#.as_slice(),
            br#"{"schema_version":"#.as_slice(),
        ] {
            std::fs::write(&record, bytes).unwrap();
            let removed = journal::sweep_if_no_pending_records(data.path(), || {
                x0x::upgrade::sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::ZERO)
            });
            assert_eq!(removed, 0);
            assert_eq!(std::fs::read(&record).unwrap(), bytes);
            assert_eq!(
                std::fs::read(staged.join("candidate")).unwrap(),
                b"candidate"
            );
            assert_eq!(std::fs::read(&sidelined).unwrap(), b"rollback");
        }
        std::fs::remove_file(record).unwrap();
    }

    let record = data.path().join(journal::HANDOFF_FILE_NAME);
    let mut m2 = serde_json::to_value(legacy_handoff(dir.path(), "0.48.2")).unwrap();
    m2["schema_version"] = serde_json::json!(1);
    m2["record_kind"] = serde_json::json!("handoff");
    m2["transaction_id"] = serde_json::json!("transaction-a");
    m2["generation"] = serde_json::json!(3);
    m2["instance_id"] = serde_json::json!("alice");
    let bytes = serde_json::to_vec(&m2).unwrap();
    std::fs::write(&record, &bytes).unwrap();
    assert!(matches!(
        journal::read_boot_records(data.path()).handoff,
        journal::RecordRead::Handoff(_)
    ));
    assert_eq!(
        journal::sweep_if_no_pending_records(data.path(), || {
            x0x::upgrade::sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::ZERO)
        }),
        0
    );
    assert_eq!(std::fs::read(&record).unwrap(), bytes);
    assert_eq!(
        std::fs::read(staged.join("candidate")).unwrap(),
        b"candidate"
    );
    assert_eq!(std::fs::read(&sidelined).unwrap(), b"rollback");
    std::fs::remove_file(&record).unwrap();
    assert_eq!(
        journal::sweep_if_no_pending_records(data.path(), || {
            x0x::upgrade::sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::ZERO)
        }),
        2
    );
}

#[test]
fn legacy_only_handoff_allows_unrelated_cleanup_and_preserves_its_files() {
    for versioned in [false, true] {
        let install = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let handoff = legacy_handoff(install.path(), "0.48.2");
        std::fs::write(&handoff.target_path, b"configured binary").unwrap();
        std::fs::write(&handoff.backup_path, b"referenced rollback").unwrap();
        let staged = install.path().join(".x0x-upgrade-unrelated");
        let sidelined = install.path().join("x0xd.x0xold-unrelated");
        std::fs::create_dir(&staged).unwrap();
        std::fs::write(staged.join("candidate"), b"unrelated stage").unwrap();
        std::fs::write(&sidelined, b"unrelated sideline").unwrap();
        let mut value = serde_json::to_value(&handoff).unwrap();
        if versioned {
            value["schema_version"] = serde_json::json!(1);
            value["record_kind"] = serde_json::json!("legacy_handoff");
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let record = data.path().join(journal::HANDOFF_FILE_NAME);
        std::fs::write(&record, &bytes).unwrap();

        // A zero minimum age makes the fixtures eligible without sleeps.
        let removed = journal::sweep_if_no_pending_records(data.path(), || {
            x0x::upgrade::sweep_stale_upgrade_artifacts(install.path(), std::time::Duration::ZERO)
        });

        assert_eq!(
            removed, 2,
            "a validated legacy-only handoff must not stop unrelated cleanup"
        );
        assert!(!staged.exists());
        assert!(!sidelined.exists());
        assert_eq!(std::fs::read(&record).unwrap(), bytes);
        assert_eq!(
            std::fs::read(&handoff.target_path).unwrap(),
            b"configured binary"
        );
        assert_eq!(
            std::fs::read(&handoff.backup_path).unwrap(),
            b"referenced rollback"
        );
    }
}

#[test]
fn legacy_handoff_referencing_a_cleanup_pattern_keeps_its_recovery_bytes() {
    for reference_staged_directory in [false, true] {
        let install = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let mut handoff = legacy_handoff(install.path(), "0.48.2");
        if reference_staged_directory {
            let staged = install.path().join(".x0x-upgrade-referenced");
            std::fs::create_dir(&staged).unwrap();
            handoff.target_path = staged.join("x0xd");
        } else {
            handoff.backup_path = install.path().join("x0xd.x0xold-referenced");
        }
        std::fs::write(&handoff.target_path, b"configured binary").unwrap();
        std::fs::write(&handoff.backup_path, b"referenced rollback").unwrap();
        let bytes = serde_json::to_vec(&handoff).unwrap();
        let record = data.path().join(journal::HANDOFF_FILE_NAME);
        std::fs::write(&record, &bytes).unwrap();

        journal::sweep_if_no_pending_records(data.path(), || {
            x0x::upgrade::sweep_stale_upgrade_artifacts(install.path(), std::time::Duration::ZERO)
        });

        assert_eq!(std::fs::read(&record).unwrap(), bytes);
        assert_eq!(
            std::fs::read(&handoff.target_path).unwrap(),
            b"configured binary"
        );
        assert_eq!(
            std::fs::read(&handoff.backup_path).unwrap(),
            b"referenced rollback"
        );
    }
}

#[cfg(not(unix))]
#[test]
fn unsupported_m2_record_barriers_refuse_before_mutation() {
    let dir = TempDir::new().unwrap();
    assert_eq!(
        journal::check_record_barrier_support(dir.path())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    let path = dir.path().join(journal::BOOT_FILE_NAME);
    let record = serde_json::json!({
        "schema_version": 1,
        "record_kind": "boot",
        "transaction_id": "transaction-a",
        "generation": 3,
        "instance_id": "alice",
        "attempt": 1,
        "pid": 5678,
        "process_start": 200,
        "boot_id": "boot-a",
        "started_at_ns": 300,
        "deadline_ns": 600
    });
    let target = dir.path().join("x0xd.exe");
    let backup = dir.path().join("x0xd.backup");
    std::fs::write(&target, b"configured binary").unwrap();
    std::fs::write(&backup, b"rollback binary").unwrap();
    for preexisting in [false, true] {
        let previous = serde_json::to_vec(&record).unwrap();
        if preexisting {
            std::fs::write(&path, &previous).unwrap();
        }
        assert_eq!(
            journal::write_record(&path, &record).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        if preexisting {
            assert_eq!(std::fs::read(&path).unwrap(), previous);
        } else {
            assert!(!path.exists());
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"configured binary");
        assert_eq!(std::fs::read(&backup).unwrap(), b"rollback binary");
    }
}

#[cfg(windows)]
#[test]
fn windows_unmanaged_legacy_handoff_still_writes_and_reads() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let mut handoff = legacy_handoff(dir.path(), "0.48.2");
    std::fs::write(&handoff.target_path, b"configured binary").unwrap();
    std::fs::write(&handoff.backup_path, b"rollback binary").unwrap();
    for version in ["0.48.2", "0.48.3"] {
        handoff.to_version = version.to_owned();
        handoff.write(&path).unwrap();

        let parsed = UpgradeHandoff::read(&path).unwrap();
        let encoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(encoded.get("schema_version").is_none());
        assert!(encoded.get("record_kind").is_none());
        assert_eq!(parsed.to_version, version);
        assert_eq!(parsed.mode, RestartMode::TransactionalHandoff);
        assert_eq!(parsed.argv, handoff.argv);
        assert_eq!(parsed.target_path, handoff.target_path);
        assert_eq!(parsed.backup_path, handoff.backup_path);
        assert_eq!(
            std::fs::read(&handoff.target_path).unwrap(),
            b"configured binary"
        );
        assert_eq!(
            std::fs::read(&handoff.backup_path).unwrap(),
            b"rollback binary"
        );
        assert_diagnostic_only(&journal::read_boot_records(dir.path()));
    }
}

#[cfg(unix)]
#[test]
fn handoff_writer_marks_diagnostic_schema_without_losing_legacy_fields() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    legacy_handoff(dir.path(), "0.48.2").write(&path).unwrap();

    let encoded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(encoded["schema_version"], 1);
    assert_eq!(encoded["record_kind"], "legacy_handoff");
    assert_eq!(encoded["from_version"], "0.48.1");
    assert_eq!(encoded["to_version"], "0.48.2");
}

#[test]
fn legacy_helper_refuses_unknown_handoff_schema_and_preserves_bytes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let legacy = serde_json::to_value(legacy_handoff(dir.path(), "0.48.2")).unwrap();
    for version in [
        serde_json::json!(2),
        serde_json::json!("1"),
        serde_json::Value::Null,
    ] {
        let mut record = legacy.clone();
        record["schema_version"] = version;
        record["record_kind"] = serde_json::json!("legacy_handoff");
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        assert!(
            UpgradeHandoff::read(&path).is_err(),
            "unknown schema must not reach the legacy helper: {record}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn legacy_helper_refuses_other_record_kinds_and_preserves_bytes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let mut record = serde_json::to_value(legacy_handoff(dir.path(), "0.48.2")).unwrap();
    record["schema_version"] = serde_json::json!(1);
    for kind in ["host_journal", "boot_state", "m2_handoff", "future_kind"] {
        record["record_kind"] = serde_json::json!(kind);
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        assert!(
            UpgradeHandoff::read(&path).is_err(),
            "a {kind} record must not become a legacy-helper instruction"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn handoff_writer_refuses_to_overwrite_unknown_or_corrupt_records() {
    for bytes in [
        b"{\"from_version\":".as_slice(),
        br#"{"schema_version":99,"record_kind":"legacy_handoff"}"#.as_slice(),
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(HANDOFF_FILE_NAME);
        std::fs::write(&path, bytes).unwrap();

        let result = legacy_handoff(dir.path(), "0.48.3").write(&path);

        assert!(
            result.is_err(),
            "a writer must preserve the refused record for diagnosis"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

fn assert_diagnostic_only(records: &journal::BootRecords) {
    assert!(
        records.configured_start_allowed(),
        "record refusal must not brick configured startup"
    );
    assert!(!records.may_apply(), "S2a cannot authorize apply");
    assert!(!records.may_recover(), "S2a cannot authorize recovery");
}

#[test]
fn missing_boot_records_allow_configured_start_without_recovery() {
    let dir = TempDir::new().unwrap();
    let records = journal::read_boot_records(dir.path());

    assert_diagnostic_only(&records);
    assert!(!records.has_records());
    assert!(records.diagnostic().is_none());
}

#[test]
fn released_legacy_handoff_is_diagnostic_only_and_preserves_referenced_files() {
    let dir = TempDir::new().unwrap();
    let handoff = legacy_handoff(dir.path(), "0.48.2");
    let bytes = serde_json::to_vec_pretty(&handoff).unwrap();
    let path = dir.path().join(HANDOFF_FILE_NAME);
    std::fs::write(&path, &bytes).unwrap();
    std::fs::write(&handoff.target_path, b"configured").unwrap();
    std::fs::write(&handoff.backup_path, b"retained rollback").unwrap();

    let records = journal::read_boot_records(dir.path());

    assert_diagnostic_only(&records);
    assert!(records.has_records());
    assert!(records.diagnostic().is_some());
    assert!(matches!(
        records.handoff,
        journal::RecordRead::LegacyHandoff(_)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(std::fs::read(&handoff.target_path).unwrap(), b"configured");
    assert_eq!(
        std::fs::read(&handoff.backup_path).unwrap(),
        b"retained rollback"
    );
}

#[test]
fn unknown_and_corrupt_boot_records_degrade_without_mutation_or_authority() {
    let fixtures: &[&[u8]] = &[
        b"",
        b"{\"schema_version\":1,",
        b"not json",
        b"null",
        b"[]",
        b"{}",
        br#"{"from_version":"0.48.1"}"#,
        br#"{"schema_version":2,"record_kind":"host_journal"}"#,
        br#"{"schema_version":"1","record_kind":"host_journal"}"#,
        br#"{"schema_version":null,"record_kind":"host_journal"}"#,
        br#"{"schema_version":1,"record_kind":"unknown_future_kind"}"#,
    ];
    for name in [
        journal::JOURNAL_FILE_NAME,
        journal::HANDOFF_FILE_NAME,
        journal::BOOT_FILE_NAME,
    ] {
        for &bytes in fixtures {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join(name);
            let configured = dir.path().join("x0xd");
            let backup = dir.path().join("x0xd.backup-0.48.1");
            std::fs::write(&path, bytes).unwrap();
            std::fs::write(&configured, b"configured").unwrap();
            std::fs::write(&backup, b"backup").unwrap();

            let records = journal::read_boot_records(dir.path());

            assert_diagnostic_only(&records);
            assert!(records.has_records());
            assert!(
                records.diagnostic().is_some(),
                "a refused {name} must report a degraded cause"
            );
            let selected = match name {
                journal::JOURNAL_FILE_NAME => &records.journal,
                journal::HANDOFF_FILE_NAME => &records.handoff,
                journal::BOOT_FILE_NAME => &records.boot,
                _ => unreachable!(),
            };
            assert!(
                matches!(selected, journal::RecordRead::Refused(_)),
                "{name} accepted invalid bytes: {bytes:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert_eq!(std::fs::read(&configured).unwrap(), b"configured");
            assert_eq!(std::fs::read(&backup).unwrap(), b"backup");
        }
    }
}

#[cfg(unix)]
#[test]
fn record_barrier_failures_are_not_acknowledged_and_never_authorize_actions() {
    for failed_step in [
        journal::BarrierStep::Write,
        journal::BarrierStep::FileSync,
        journal::BarrierStep::Rename,
        journal::BarrierStep::DirectorySync,
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(journal::HANDOFF_FILE_NAME);
        let old_record = legacy_handoff(dir.path(), "0.48.2");
        old_record.write(&path).unwrap();
        let old_bytes = std::fs::read(&path).unwrap();
        let mut new_record = serde_json::to_value(legacy_handoff(dir.path(), "0.48.3")).unwrap();
        new_record["schema_version"] = serde_json::json!(1);
        new_record["record_kind"] = serde_json::json!("legacy_handoff");

        let outcome = journal::write_record_with_failure(&path, &new_record, failed_step);

        assert!(outcome.is_err(), "a failed barrier cannot be acknowledged");
        let current = UpgradeHandoff::read(&path).unwrap();
        if matches!(failed_step, journal::BarrierStep::DirectorySync) {
            // The rename has happened, but its parent sync failed. A complete
            // visible record is still not proof that its barrier succeeded.
            assert_eq!(current.to_version, "0.48.3");
        } else {
            assert_eq!(current.to_version, "0.48.2");
            assert_eq!(std::fs::read(&path).unwrap(), old_bytes);
        }
        let records = journal::read_boot_records(dir.path());
        assert_diagnostic_only(&records);
        assert!(records.diagnostic().is_some());
    }
}

#[cfg(unix)]
fn journal_fixture(root: &Path) -> serde_json::Value {
    let artifact = |name: &str| {
        serde_json::json!({
            "target_path": root.join(name),
            "staged_path": root.join(format!("{name}.staged")),
            "backup_path": root.join(format!("{name}.backup-0.48.1")),
            "previous_sha256": vec![1_u8; 32],
            "candidate_sha256": vec![2_u8; 32],
        })
    };
    serde_json::json!({
        "schema_version": 1,
        "record_kind": "journal",
        "transaction_id": "transaction-a",
        "sequence": 7,
        "generation": 3,
        "plan": {
            "previous_version": "0.48.1",
            "candidate_version": "0.48.2",
            "manifest_sha256": vec![3_u8; 32],
            "daemon": artifact("x0xd"),
            "cli": artifact("x0x"),
            "participants": [{
                "instance_id": "alice",
                "executable": root.join("x0xd"),
                "data_root": root.join("data"),
                "identity_root": root.join("identity"),
                "argv": ["x0xd", "--name", "alice"],
                "cwd": root,
                "env": {},
                "restart": {
                    "mode": "TransactionalHandoff",
                    "supervised_exit_code": null,
                    "supervision_signal": null,
                    "launchd_verified": null,
                    "systemd_verified": null,
                    "launcher": null
                },
                "old_pid": 1234,
                "process_start": 100,
                "boot_id": "boot-a",
                "was_running": true
            }]
        },
        "phase": "prepared",
        "cause": null,
        "daemon_progress": {
            "swapped": false, "restored": false, "observed_sha256": null
        },
        "cli_progress": {
            "swapped": false, "restored": false, "observed_sha256": null
        }
    })
}

#[cfg(unix)]
#[test]
fn versioned_journal_preserves_frozen_plan_and_never_arms_recovery() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(journal::JOURNAL_FILE_NAME);
    let record = journal_fixture(dir.path());
    journal::write_record(&path, &record).unwrap();
    let bytes = std::fs::read(&path).unwrap();

    let records = journal::read_boot_records(dir.path());

    assert_diagnostic_only(&records);
    assert!(records.diagnostic().is_some());
    let journal::RecordRead::Journal(parsed) = records.journal else {
        panic!("valid journal must remain available for diagnosis");
    };
    assert_eq!(serde_json::to_value(parsed).unwrap(), record);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn every_recorded_journal_phase_remains_dormant_until_launcher_integration() {
    for phase in [
        "staged",
        "probed",
        "prepared",
        "swapped_daemon",
        "swapped_cli",
        "handoff_armed",
        "booting",
        "health_committed",
        "host_committed",
        "rolling_back",
        "failed_release_hold",
        "restored",
        "recovery_failed",
        "idle",
        "superseded",
    ] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(journal::JOURNAL_FILE_NAME);
        let mut record = journal_fixture(dir.path());
        record["phase"] = serde_json::json!(phase);
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let records = journal::read_boot_records(dir.path());

        assert_diagnostic_only(&records);
        assert!(
            matches!(records.journal, journal::RecordRead::Journal(_)),
            "known phase {phase} must remain readable"
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn versioned_handoff_and_boot_bind_identity_without_granting_authority() {
    let dir = TempDir::new().unwrap();
    let mut handoff = serde_json::to_value(legacy_handoff(dir.path(), "0.48.2")).unwrap();
    handoff["schema_version"] = serde_json::json!(1);
    handoff["record_kind"] = serde_json::json!("handoff");
    handoff["transaction_id"] = serde_json::json!("transaction-a");
    handoff["generation"] = serde_json::json!(3);
    handoff["instance_id"] = serde_json::json!("alice");
    let boot = serde_json::json!({
        "schema_version": 1,
        "record_kind": "boot",
        "transaction_id": "transaction-a",
        "generation": 3,
        "instance_id": "alice",
        "attempt": 1,
        "pid": 5678,
        "process_start": 200,
        "boot_id": "boot-a",
        "started_at_ns": 300,
        "deadline_ns": 600
    });
    let handoff_path = dir.path().join(journal::HANDOFF_FILE_NAME);
    let boot_path = dir.path().join(journal::BOOT_FILE_NAME);
    journal::write_record(&handoff_path, &handoff).unwrap();
    journal::write_record(&boot_path, &boot).unwrap();

    let records = journal::read_boot_records(dir.path());

    assert_diagnostic_only(&records);
    let journal::RecordRead::Handoff(parsed_handoff) = records.handoff else {
        panic!("valid M2 handoff must remain readable");
    };
    let journal::RecordRead::Boot(parsed_boot) = records.boot else {
        panic!("valid boot record must remain readable");
    };
    assert_eq!(parsed_handoff.transaction_id, parsed_boot.transaction_id);
    assert_eq!(parsed_handoff.generation, parsed_boot.generation);
    assert_eq!(parsed_handoff.instance_id, parsed_boot.instance_id);
    assert_eq!(serde_json::to_value(parsed_handoff).unwrap(), handoff);
    assert_eq!(serde_json::to_value(parsed_boot).unwrap(), boot);
    assert!(UpgradeHandoff::read(&handoff_path).is_err());
}

#[test]
fn restart_preflight_allows_clean_data_root() {
    let dir = TempDir::new().unwrap();
    let executable = dir.path().join("x0xd");
    std::fs::write(&executable, b"configured").unwrap();

    let plan = resolve_restart_plan(
        false,
        &SupervisionSignals::default(),
        &executable,
        Some(dir.path()),
        None,
        &LaunchdPolicyReadback::Unavailable {
            detail: "filesystem-only fixture".to_string(),
        },
        &SystemdPolicyReadback::NotApplicable,
    )
    .expect("no record means no unresolved upgrade intent");

    assert_eq!(plan.mode, RestartMode::TransactionalHandoff);
    assert_eq!(std::fs::read(&executable).unwrap(), b"configured");
}

#[test]
fn released_legacy_handoff_does_not_permanently_block_new_preflight() {
    let dir = TempDir::new().unwrap();
    let handoff = legacy_handoff(dir.path(), "0.48.2");
    let path = dir.path().join(HANDOFF_FILE_NAME);
    let legacy_bytes = serde_json::to_vec(&handoff).unwrap();
    std::fs::write(&handoff.target_path, b"configured").unwrap();
    std::fs::write(&handoff.backup_path, b"retained rollback").unwrap();
    std::fs::write(&path, &legacy_bytes).unwrap();

    let result = resolve_restart_plan(
        false,
        &SupervisionSignals::default(),
        &handoff.target_path,
        Some(dir.path()),
        None,
        &LaunchdPolicyReadback::Unavailable {
            detail: "filesystem-only fixture".to_string(),
        },
        &SystemdPolicyReadback::NotApplicable,
    );

    assert!(
        result.is_ok(),
        "released diagnostic intent is not an M2 hold"
    );
    assert_diagnostic_only(&journal::read_boot_records(dir.path()));
    assert_eq!(std::fs::read(&path).unwrap(), legacy_bytes);
    assert_eq!(std::fs::read(&handoff.target_path).unwrap(), b"configured");
    assert_eq!(
        std::fs::read(&handoff.backup_path).unwrap(),
        b"retained rollback"
    );
}

#[test]
fn restart_preflight_refuses_untrusted_records_without_changing_files() {
    for name in [
        journal::JOURNAL_FILE_NAME,
        journal::HANDOFF_FILE_NAME,
        journal::BOOT_FILE_NAME,
    ] {
        for bytes in [
            b"{\"schema_version\":1,".as_slice(),
            br#"{"schema_version":99,"record_kind":"unknown"}"#.as_slice(),
        ] {
            let dir = TempDir::new().unwrap();
            let executable = dir.path().join("x0xd");
            let record_path = dir.path().join(name);
            std::fs::write(&executable, b"configured").unwrap();
            std::fs::write(&record_path, bytes).unwrap();

            let result = resolve_restart_plan(
                false,
                &SupervisionSignals::default(),
                &executable,
                Some(dir.path()),
                None,
                &LaunchdPolicyReadback::Unavailable {
                    detail: "filesystem-only fixture".to_string(),
                },
                &SystemdPolicyReadback::NotApplicable,
            );

            assert!(
                matches!(result, Err(RestartOwnershipError::Unresolved { .. })),
                "the apply preflight accepted an untrusted {name}: {result:?}"
            );
            assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
            assert_eq!(std::fs::read(&executable).unwrap(), b"configured");
            assert_diagnostic_only(&journal::read_boot_records(dir.path()));
        }
    }
}
