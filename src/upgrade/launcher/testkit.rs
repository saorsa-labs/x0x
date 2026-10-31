//! Shared inert fixtures for the refusal and run-loop tests. Canonical
//! paths, real bytes and a real journal record, with no live process: only
//! paths that need no process custody may use this builder.
use super::filesystem::hash;
use super::*;
use std::collections::BTreeMap;

/// Returns the disposable directory (keep it alive for the test), the
/// canonical fixture root, a Host bound to the record, and the record.
pub(super) fn fixture(
    phase: journal::Phase,
) -> (
    tempfile::TempDir,
    PathBuf,
    recovery::Host,
    journal::JournalRecord,
) {
    fixture_with(phase, |_| {})
}

/// As `fixture`, but `edit` changes the record before the journal is
/// written and the Host is bound (for example, to freeze a live OLD child).
pub(super) fn fixture_with(
    phase: journal::Phase,
    edit: impl FnOnce(&mut journal::JournalRecord),
) -> (
    tempfile::TempDir,
    PathBuf,
    recovery::Host,
    journal::JournalRecord,
) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let artifact = |name: &str| {
        let target = root.join(format!("{name}.d"));
        let backup = root.join(format!("{name}.b"));
        std::fs::write(&target, format!("candidate-{name}")).unwrap();
        std::fs::write(&backup, format!("previous-{name}")).unwrap();
        journal::ArtifactPlan {
            target_path: target,
            staged_path: root.join(format!("{name}.s")),
            backup_path: backup,
            previous_sha256: hash(&root.join(format!("{name}.b"))).unwrap(),
            candidate_sha256: hash(&root.join(format!("{name}.d"))).unwrap(),
        }
    };
    let daemon = artifact("daemon");
    let cli = artifact("cli");
    let participant = journal::Participant {
        instance_id: "alice".into(),
        executable: daemon.target_path.clone(),
        data_root: root.clone(),
        identity_root: root.clone(),
        argv: vec![daemon.target_path.to_string_lossy().into_owned()],
        cwd: root.clone(),
        env: BTreeMap::new(),
        restart: journal::RestartBinding {
            mode: journal::RestartOwner::LauncherChild,
            supervised_exit_code: None,
            supervision_signal: None,
            launchd_verified: None,
            systemd_verified: None,
            launcher: Some(journal::LauncherBinding {
                executable: root.join("x0x-launcher"),
                argv: vec![root.join("x0x-launcher").to_string_lossy().into_owned()],
                pid: Some(4243),
                process_start: Some(78),
                boot_id: "fixture-boot".into(),
                manager_exit_code: 0,
            }),
        },
        old_pid: Some(4242),
        process_start: Some(77),
        boot_id: "fixture-boot".into(),
        was_running: true,
    };
    let mut record = journal::JournalRecord {
        schema_version: 1,
        record_kind: "journal".into(),
        transaction_id: "refusal-fixture".into(),
        sequence: 1,
        generation: 1,
        plan: journal::FrozenPlan {
            previous_version: "0.0.1".into(),
            candidate_version: "9.9.9".into(),
            manifest_sha256: [7; 32],
            daemon,
            cli,
            participants: vec![participant],
        },
        phase,
        cause: None,
        daemon_progress: journal::ArtifactProgress {
            swapped: true,
            restored: false,
            observed_sha256: None,
        },
        cli_progress: journal::ArtifactProgress {
            swapped: true,
            restored: false,
            observed_sha256: None,
        },
    };
    edit(&mut record);
    journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
    let host = recovery::Host::new(root.clone(), record.clone()).unwrap();
    (dir, root, host, record)
}
