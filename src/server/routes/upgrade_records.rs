//! #1381 M2 part: the upgrade records that `GET /diagnostics/upgrade`
//! reports (A14 amendment of 15 Nov 2026).
//!
//! Everything here is a read of fixed record names. It never follows a path
//! taken from a record, never removes or repairs a record, and never copies
//! participant arguments, environment or free-text causes, which can hold
//! credentials.

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::upgrade::journal::{self, RecordRead};
#[cfg(unix)]
use crate::upgrade::probe::{self, ProbePhase};

/// The most backup files the inventory lists.
const MAX_BACKUPS: usize = 32;

/// Build the `plan`, `last_attempt`, `backups`, `holds`, `last_hold_clear`
/// and `records_error` fields. `install` is the canonical daemon executable,
/// or `None` when it cannot be resolved.
pub(super) fn records_json(data_dir: &Path, install: Option<&Path>) -> Map<String, Value> {
    let mut errors = Vec::new();
    let mut body = Map::new();
    body.insert("plan".into(), plan_json(data_dir, &mut errors));

    if install.is_none() {
        errors.push("install path unavailable");
    }
    probe_records_json(install, &mut body, &mut errors);
    body.insert(
        "backups".into(),
        Value::Array(install.map(backups_json).unwrap_or_default()),
    );
    body.insert("launcher_gate".into(), launcher_gate_json());
    body.insert(
        "companion_failure".into(),
        crate::upgrade::companion_failure::current(data_dir)
            .and_then(|record| serde_json::to_value(record).ok())
            .unwrap_or(Value::Null),
    );
    body.insert(
        "records_error".into(),
        if errors.is_empty() {
            Value::Null
        } else {
            Value::String(errors.join("; "))
        },
    );
    body
}

/// The prepare producer's last gate decision in this process (#2012):
/// whether the launcher-protected path ran for the last apply and why not.
/// `null` before the first apply since the daemon started.
fn launcher_gate_json() -> Value {
    #[cfg(unix)]
    {
        crate::upgrade::producer::last_gate()
            .and_then(|gate| serde_json::to_value(gate).ok())
            .unwrap_or(Value::Null)
    }
    #[cfg(not(unix))]
    {
        Value::Null
    }
}

/// The `last_attempt`, `holds` and `last_hold_clear` fields, from the
/// install's pre-swap probe records.
#[cfg(unix)]
fn probe_records_json(
    install: Option<&Path>,
    body: &mut Map<String, Value>,
    errors: &mut Vec<&'static str>,
) {
    let probe_state = match install.map(probe::read_state) {
        Some(Ok(state)) => state,
        Some(Err(_)) => {
            errors.push("probe record unreadable");
            None
        }
        None => None,
    };
    body.insert(
        "last_attempt".into(),
        probe_state.as_ref().map_or(Value::Null, |state| {
            json!({
                "version": state.version,
                "transaction_id": state.transaction_id,
                "attempt": state.attempt,
                "phase": state.phase,
                "cause": state.cause,
                "retry_remaining_ms": state.retry_remaining_ms,
            })
        }),
    );
    // `clearable` must match `probe::clear_failed_hold`: an unresolved
    // `.pending` terminalization marker or a latched barrier failure blocks
    // every local clear, and the marker is itself a hold.
    let blocker = match install.map(probe::clear_blocker) {
        Some(Ok(blocker)) => blocker,
        Some(Err(_)) => {
            errors.push("probe terminalization record unreadable");
            Some("unreadable")
        }
        None => None,
    };
    let mut holds = Vec::new();
    if blocker.is_some() {
        holds.push(json!({
            "version": probe_state.as_ref().map(|state| state.version.clone()),
            "kind": "unresolved_probe_record",
            "cause": Value::Null,
            "clearable": false,
        }));
    }
    if let Some(state) = &probe_state {
        let held = match state.phase {
            ProbePhase::FailedHold => Some(("failed_release", blocker.is_none())),
            // D190: only a failed-release hold has a local clear.
            ProbePhase::RecoveryFailed => Some(("recovery_failed", false)),
            _ => None,
        };
        if let Some((kind, clearable)) = held {
            holds.push(json!({
                "version": state.version,
                "kind": kind,
                "cause": state.cause,
                "clearable": clearable,
            }));
        }
    }
    body.insert("holds".into(), Value::Array(holds));

    let last_clear = match install.map(probe::read_clear_receipt) {
        Some(Ok(Some(receipt))) => json!({
            "version": receipt.version,
            "cause": receipt.cause,
            "cleared_at_unix": receipt.cleared_at_unix,
        }),
        Some(Err(_)) => {
            errors.push("hold clear receipt unreadable");
            Value::Null
        }
        _ => Value::Null,
    };
    body.insert("last_hold_clear".into(), last_clear);
}

/// Probe records and holds exist only on Unix installs (`upgrade::probe`), so
/// the fields keep their documented shape with the "no record" values.
#[cfg(not(unix))]
fn probe_records_json(
    _install: Option<&Path>,
    body: &mut Map<String, Value>,
    _errors: &mut Vec<&'static str>,
) {
    body.insert("last_attempt".into(), Value::Null);
    body.insert("holds".into(), Value::Array(Vec::new()));
    body.insert("last_hold_clear".into(), Value::Null);
}

/// The frozen plan of the M2 journal, if a record exists.
fn plan_json(data_dir: &Path, errors: &mut Vec<&'static str>) -> Value {
    let records = journal::read_boot_records(data_dir);
    // Each refused record is named by fixed text: parser errors can quote
    // a malformed record. A refused boot record alone must still show.
    for (read, name) in [
        (&records.journal, "journal record unreadable"),
        (&records.handoff, "handoff record unreadable"),
        (&records.boot, "boot record unreadable"),
    ] {
        if matches!(read, RecordRead::Refused(_)) {
            errors.push(name);
        }
    }
    let boot_attempt = match &records.boot {
        RecordRead::Boot(boot) => Some(boot.attempt),
        _ => None,
    };
    match &records.journal {
        RecordRead::Journal(record) => json!({
            "record": "journal",
            "transaction_id": record.transaction_id,
            "phase": record.phase,
            "previous_version": record.plan.previous_version,
            "candidate_version": record.plan.candidate_version,
            "participants": record.plan.participants.len(),
            "cause": record.cause.as_ref().map(|cause| cause.class),
            "boot_attempt": boot_attempt,
        }),
        // Parser errors can quote a malformed record: name the state only.
        RecordRead::Refused(_) => json!({ "record": "refused" }),
        RecordRead::Missing => match &records.handoff {
            RecordRead::Missing => Value::Null,
            RecordRead::LegacyHandoff(_) => json!({ "record": "legacy_handoff" }),
            RecordRead::Refused(_) => json!({ "record": "refused" }),
            _ => json!({ "record": "handoff", "boot_attempt": boot_attempt }),
        },
        _ => json!({ "record": "unexpected" }),
    }
}

/// Backup files beside the daemon and its sibling CLI: the legacy
/// `<name>.backup` and the M2 pair's `<name>.backup-<version>-<transaction>`.
fn backups_json(install: &Path) -> Vec<Value> {
    let Some(dir) = install.parent() else {
        return Vec::new();
    };
    let daemon = install
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let cli = crate::upgrade::apply::cli_file_name();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, &'static str, std::fs::Metadata)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let artifact = [(daemon.as_str(), "daemon"), (cli, "cli")]
                .into_iter()
                .find(|(base, _)| !base.is_empty() && is_backup_name(&name, base))
                .map(|(_, artifact)| artifact)?;
            let metadata = entry.path().symlink_metadata().ok()?;
            metadata
                .file_type()
                .is_file()
                .then_some((name, artifact, metadata))
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.truncate(MAX_BACKUPS);
    found
        .into_iter()
        .map(|(name, artifact, metadata)| {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_secs());
            json!({
                "artifact": artifact,
                "name": name,
                "size_bytes": metadata.len(),
                "modified_unix": modified,
            })
        })
        .collect()
}

fn is_backup_name(name: &str, base: &str) -> bool {
    name.strip_prefix(base)
        .and_then(|rest| rest.strip_prefix(".backup"))
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_names_match_legacy_and_pair_forms_only() {
        assert!(is_backup_name("x0xd.backup", "x0xd"));
        assert!(is_backup_name("x0xd.backup-0.48.0-abc", "x0xd"));
        assert!(!is_backup_name("x0xd.backups", "x0xd"));
        assert!(!is_backup_name("x0xd.candidate-0.48.1-abc", "x0xd"));
        assert!(!is_backup_name("x0x.backup", "x0xd"));
    }

    #[test]
    fn empty_install_reports_no_records() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let install = dir.path().join("x0xd");
        std::fs::write(&install, b"daemon").expect("install");
        let install = install.canonicalize().expect("canonical");
        let body = records_json(dir.path(), Some(&install));
        assert_eq!(body["plan"], Value::Null);
        assert_eq!(body["last_attempt"], Value::Null);
        assert_eq!(body["holds"], json!([]));
        assert_eq!(body["last_hold_clear"], Value::Null);
        assert_eq!(body["backups"], json!([]));
        assert_eq!(body["records_error"], Value::Null);
    }

    #[test]
    fn backups_list_daemon_and_cli_files_and_skip_others() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let install = dir.path().join("x0xd");
        std::fs::write(&install, b"daemon").expect("install");
        std::fs::write(dir.path().join("x0xd.backup"), b"old").expect("legacy");
        std::fs::write(dir.path().join("x0xd.backup-0.48.0-t1"), b"pair").expect("pair");
        let cli = crate::upgrade::apply::cli_file_name();
        std::fs::write(dir.path().join(format!("{cli}.backup-0.48.0-t1")), b"c").expect("cli");
        std::fs::write(dir.path().join("x0xd.candidate-0.48.1-t1"), b"new").expect("candidate");
        let install = install.canonicalize().expect("canonical");
        let body = records_json(dir.path(), Some(&install));
        let backups = body["backups"].as_array().expect("array");
        let names: Vec<_> = backups
            .iter()
            .map(|backup| (backup["artifact"].as_str(), backup["name"].as_str()))
            .collect();
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(names.contains(&(Some("daemon"), Some("x0xd.backup"))));
        assert!(names.contains(&(Some("daemon"), Some("x0xd.backup-0.48.0-t1"))));
        assert!(names.contains(&(
            Some("cli"),
            Some(format!("{cli}.backup-0.48.0-t1").as_str())
        )));
        let legacy = backups
            .iter()
            .find(|backup| backup["name"] == "x0xd.backup")
            .expect("legacy backup");
        assert_eq!(legacy["size_bytes"], 3);
    }

    #[test]
    fn unresolved_install_is_named_as_a_records_error() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let body = records_json(dir.path(), None);
        assert_eq!(body["records_error"], "install path unavailable");
        assert_eq!(body["backups"], json!([]));
    }

    #[cfg(unix)]
    fn write_probe_record(install: &Path, phase: ProbePhase, cause: probe::ProbeCause) {
        let state = probe::ProbeState {
            schema_version: 1,
            record_kind: "probe".into(),
            install: install.to_path_buf(),
            version: "9.9.9".into(),
            platform: "test-platform".into(),
            archive_sha256: [7; 32],
            transaction_id: "00000000-0000-4000-8000-000000000001".into(),
            attempt: 4,
            phase,
            cause: Some(cause),
            last_pid: None,
            boot_id: "test-boot".into(),
            retry_remaining_ms: 0,
            retry_deadline_ms: 0,
            daemon_sha256: None,
            cli_sha256: None,
        };
        journal::write_auxiliary_record(
            &probe::state_path(install).expect("state path"),
            &state,
            |_| Ok(()),
        )
        .expect("probe record");
    }

    // A failed-release hold is listed as clearable with its last attempt;
    // after the D190 clear it is gone and the receipt is reported.
    #[cfg(unix)]
    #[test]
    fn failed_hold_then_its_clear_receipt_are_reported() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let install = dir.path().join("x0xd");
        std::fs::write(&install, b"daemon").expect("install");
        let install = install.canonicalize().expect("canonical");
        write_probe_record(
            &install,
            ProbePhase::FailedHold,
            probe::ProbeCause::RetriesExhausted,
        );

        let body = records_json(dir.path(), Some(&install));
        assert_eq!(
            body["holds"],
            json!([{
                "version": "9.9.9",
                "kind": "failed_release",
                "cause": "retries_exhausted",
                "clearable": true,
            }])
        );
        assert_eq!(body["last_attempt"]["attempt"], 4);
        assert_eq!(body["last_attempt"]["phase"], "failed_hold");
        assert_eq!(
            body["last_attempt"]["transaction_id"],
            "00000000-0000-4000-8000-000000000001"
        );

        assert!(matches!(
            probe::clear_failed_hold(&install, "9.9.9"),
            Ok(probe::HoldClear::Cleared(_))
        ));
        let body = records_json(dir.path(), Some(&install));
        assert_eq!(body["holds"], json!([]));
        assert_eq!(body["last_hold_clear"]["version"], "9.9.9");
        assert_eq!(body["last_hold_clear"]["cause"], "retries_exhausted");
        assert_eq!(body["records_error"], Value::Null);
    }

    #[cfg(unix)]
    #[test]
    fn recovery_failed_is_a_hold_with_no_local_clear() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let install = dir.path().join("x0xd");
        std::fs::write(&install, b"daemon").expect("install");
        let install = install.canonicalize().expect("canonical");
        write_probe_record(
            &install,
            ProbePhase::RecoveryFailed,
            probe::ProbeCause::HoldWriteFailed,
        );
        let body = records_json(dir.path(), Some(&install));
        assert_eq!(body["holds"][0]["kind"], "recovery_failed");
        assert_eq!(body["holds"][0]["clearable"], false);
    }

    #[test]
    fn a_corrupt_journal_is_reported_without_its_contents() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(
            dir.path().join(journal::JOURNAL_FILE_NAME),
            b"{\"secret\":\"token-123\"",
        )
        .expect("journal");
        let body = records_json(dir.path(), None);
        assert_eq!(body["plan"], json!({ "record": "refused" }));
        assert!(body["records_error"]
            .as_str()
            .expect("records error")
            .contains("journal record unreadable"));
        assert!(!serde_json::to_string(&body)
            .expect("json")
            .contains("token-123"));
    }

    // #1932 review: an unreadable boot record alone names a records error,
    // without its contents.
    #[test]
    fn an_unreadable_boot_record_alone_is_a_records_error() {
        let dir = tempfile::tempdir().expect("tmpdir");
        std::fs::write(
            dir.path().join(journal::BOOT_FILE_NAME),
            b"{\"secret\":\"token-456\"",
        )
        .expect("boot");
        let body = records_json(dir.path(), None);
        assert!(body["records_error"]
            .as_str()
            .expect("records error")
            .contains("boot record unreadable"));
        assert!(!serde_json::to_string(&body)
            .expect("json")
            .contains("token-456"));
    }

    // #1932 review: with the `.pending` terminalization marker present,
    // `clear_failed_hold` refuses, so the hold is not clearable and the
    // marker is listed as its own hold.
    #[cfg(unix)]
    #[test]
    fn a_pending_marker_makes_the_failed_hold_not_clearable() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let install = dir.path().join("x0xd");
        std::fs::write(&install, b"daemon").expect("install");
        let install = install.canonicalize().expect("canonical");
        write_probe_record(
            &install,
            ProbePhase::FailedHold,
            probe::ProbeCause::RetriesExhausted,
        );
        std::fs::write(
            probe::uncertainty_path(&install).expect("marker path"),
            b"{}",
        )
        .expect("marker");

        let body = records_json(dir.path(), Some(&install));
        let holds = body["holds"].as_array().expect("holds");
        assert_eq!(holds.len(), 2, "{holds:?}");
        assert_eq!(holds[0]["kind"], "unresolved_probe_record");
        assert_eq!(holds[0]["clearable"], false);
        assert_eq!(holds[1]["kind"], "failed_release");
        assert_eq!(holds[1]["clearable"], false);
        assert!(matches!(
            probe::clear_failed_hold(&install, "9.9.9"),
            Err(probe::ProbeRefusal::RecoveryFailed { .. })
        ));
    }

    // #1939 review: a probe record barrier failure latched in this daemon
    // process also blocks every local clear, so it is listed as an
    // `unresolved_probe_record` hold and the failed hold is not clearable.
    #[cfg(unix)]
    #[test]
    fn a_latched_barrier_makes_the_failed_hold_not_clearable() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let install = dir.path().join("x0xd");
        std::fs::write(&install, b"daemon").expect("install");
        let install = install.canonicalize().expect("canonical");
        write_probe_record(
            &install,
            ProbePhase::FailedHold,
            probe::ProbeCause::RetriesExhausted,
        );
        probe::latch_for_test(&install).expect("latch");

        let body = records_json(dir.path(), Some(&install));
        let holds = body["holds"].as_array().expect("holds");
        assert_eq!(holds.len(), 2, "{holds:?}");
        assert_eq!(holds[0]["kind"], "unresolved_probe_record");
        assert_eq!(holds[1]["kind"], "failed_release");
        assert_eq!(holds[1]["clearable"], false);
        assert!(matches!(
            probe::clear_failed_hold(&install, "9.9.9"),
            Err(probe::ProbeRefusal::RecoveryFailed { .. })
        ));
    }
}
