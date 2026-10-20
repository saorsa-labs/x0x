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
#[allow(dead_code)]
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
        &LaunchdPolicyReadback::NotApplicable,
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
        &LaunchdPolicyReadback::NotApplicable,
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
                &LaunchdPolicyReadback::NotApplicable,
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
