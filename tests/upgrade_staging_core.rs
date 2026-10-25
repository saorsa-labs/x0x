// Included and invoked inside upgrade::staging by the lead.
// The standalone integration target is inert. These tests use real private
// receipt I/O and owned filesystem fixtures; no startup or apply runtime runs.
#[allow(unused_macros)]
macro_rules! staging_core_regression_tests {
    () => {
        #[cfg(unix)]
        mod staging_core_regressions {
            use super::*;
            use crate::upgrade::{journal::BarrierStep, probe::ProbeClock};
            use std::{fs, time::Duration};

            fn fixture() -> (tempfile::TempDir, StagingRequest, fs::File) {
                let root = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| {
                        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join(".planning/upgrade-staging-fixtures")
                    });
                fs::create_dir_all(&root).unwrap();
                let dir = tempfile::Builder::new().prefix("receipt-").tempdir_in(root).unwrap();
                let root = fs::canonicalize(dir.path()).unwrap();
                fs::write(root.join("x0xd"), b"owned installed fixture").unwrap();
                fs::create_dir(root.join("data")).unwrap();
                fs::create_dir(root.join("identity")).unwrap();
                let request = StagingRequest {
                    install: root.join("x0xd"), data_root: root.join("data"),
                    identity_root: root.join("identity"), machine_id: [42; 32],
                    version: "1.2.3".into(), manifest_sha256: [3; 32],
                    archive_sha256: [4; 32], window_minutes: 60,
                };
                let lock = crate::upgrade::acquire_host_upgrade_lock(&request.install).unwrap();
                (dir, request, lock)
            }

            fn clock(boot: &str, milliseconds: u64) -> ProbeClock {
                ProbeClock { boot_id: boot.into(), monotonic_ms: milliseconds }
            }

            #[test]
            fn staging_receipt_keeps_first_choice_and_subsecond_elapsed_across_fresh_reads() {
                let (_dir, request, _lock) = fixture();
                assert_eq!(observe(&request, &clock("a", 1000)).unwrap(),
                    Decision::Waiting(Duration::from_secs(2532)));
                assert_eq!(observe(&request, &clock("a", 1500)).unwrap(),
                    Decision::Waiting(Duration::from_millis(2_531_500)));
                let mut fresh_request = request.clone();
                fresh_request.window_minutes = 0;
                assert_eq!(receipt_path(&request).unwrap(), receipt_path(&fresh_request).unwrap());
                assert_eq!(observe(&fresh_request, &clock("a", 2000)).unwrap(),
                    Decision::Waiting(Duration::from_secs(2531)));
                let saved = read_receipt(&fresh_request).unwrap().unwrap();
                assert_eq!(saved.window_minutes, 60);
                assert_eq!(saved.chosen_delay, Duration::from_secs(2532));
                assert_eq!(saved.first_boot_id, "a");
                assert_eq!(saved.first_receipt_ms, 1000);
                assert_eq!(saved.remaining, Duration::from_secs(2531));
                assert_eq!(saved.manifest_sha256, [3; 32]);
                assert_eq!(saved.archive_sha256, [4; 32]);
            }

            #[test]
            fn staging_reboot_retains_remaining_and_backwards_monotonic_preserves_bytes() {
                let (_dir, request, _lock) = fixture();
                observe(&request, &clock("a", 1000)).unwrap();
                observe(&request, &clock("a", 3000)).unwrap();
                assert_eq!(observe(&request, &clock("b", 9_000_000)).unwrap(),
                    Decision::Waiting(Duration::from_secs(2530)));
                assert_eq!(observe(&request, &clock("b", 9_001_000)).unwrap(),
                    Decision::Waiting(Duration::from_secs(2529)));
                let path = receipt_path(&request).unwrap();
                let before = fs::read(&path).unwrap();
                assert!(observe(&request, &clock("b", 8_000_000)).is_err());
                assert_eq!(fs::read(path).unwrap(), before);
                let saved = read_receipt(&request).unwrap().unwrap();
                assert_eq!(saved.first_boot_id, "a");
                assert_eq!(saved.first_receipt_ms, 1000);
            }

            #[test]
            fn staging_zero_remaining_after_reboot_needs_recorded_elapsed_evidence() {
                let (_dir, request, _lock) = fixture();
                observe(&request, &clock("a", 1000)).unwrap();
                observe(&request, &clock("a", 3000)).unwrap();
                assert_eq!(observe(&request, &clock("b", 9000)).unwrap(),
                    Decision::Waiting(Duration::from_secs(2530)));
                assert_eq!(observe(&request, &clock("b", 9500)).unwrap(),
                    Decision::Waiting(Duration::from_millis(2_529_500)));
                let checkpoint = read_receipt(&request).unwrap().unwrap();
                assert_eq!(checkpoint.epoch_anchor_ms, 9000);
                assert_eq!(checkpoint.epoch_remaining, Duration::from_secs(2530));
                let path = receipt_path(&request).unwrap();
                let valid = fs::read(&path).unwrap();
                for field in ["remaining", "epoch_anchor_ms", "epoch_remaining"] {
                    let mut corrupt: serde_json::Value = serde_json::from_slice(&valid).unwrap();
                    corrupt[field] = match field {
                        "remaining" => serde_json::json!({"secs":0,"nanos":0}),
                        "epoch_anchor_ms" => serde_json::json!(9501),
                        _ => serde_json::json!({"secs":2533,"nanos":0}),
                    };
                    let corrupt = serde_json::to_vec(&corrupt).unwrap();
                    fs::write(&path, &corrupt).unwrap();
                    assert!(read_receipt(&request).is_err(), "{field}");
                    assert!(observe(&request, &clock("b", 9500)).is_err(), "{field}");
                    assert_eq!(fs::read(&path).unwrap(), corrupt);
                }
                fs::write(&path, valid).unwrap();
                assert_eq!(observe(&request, &clock("b", 10_000)).unwrap(),
                    Decision::Waiting(Duration::from_secs(2529)));
            }

            #[test]
            fn staging_conflicting_signed_payloads_cannot_choose_a_new_receipt() {
                let (_dir, request, _lock) = fixture();
                observe(&request, &clock("a", 1000)).unwrap();
                let path = receipt_path(&request).unwrap();
                let before = fs::read(&path).unwrap();
                for manifest_conflict in [false, true] {
                    let mut conflicting = request.clone();
                    if manifest_conflict { conflicting.manifest_sha256 = [9; 32]; }
                    else { conflicting.archive_sha256 = [9; 32]; }
                    assert_eq!(receipt_path(&conflicting).unwrap(), path);
                    assert!(observe(&conflicting, &clock("a", 2000)).is_err());
                    assert_eq!(fs::read(&path).unwrap(), before);
                }
            }

            #[test]
            fn staging_corrupt_unknown_and_impossible_receipts_are_preserved() {
                let (_dir, request, _lock) = fixture();
                observe(&request, &clock("a", 1000)).unwrap();
                let path = receipt_path(&request).unwrap();
                let valid: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                let mut bad = vec![b"{torn".to_vec()];
                for field in ["schema_version", "record_kind", "remaining", "install",
                    "data_root", "identity_root", "machine_id", "version", "extra", "nanos",
                    "nested_extra"] {
                    let mut value = valid.clone();
                    match field {
                        "schema_version" => value[field] = serde_json::json!(99),
                        "record_kind" => value[field] = serde_json::json!("unknown"),
                        // No elapsed time was recorded: zero remaining is impossible.
                        "remaining" => value[field] = serde_json::json!({"secs":0,"nanos":0}),
                        "install" => value[field] = serde_json::json!("relative"),
                        "data_root" | "identity_root" => value[field] = serde_json::json!("/wrong-root"),
                        "machine_id" => value[field][0] = serde_json::json!(99),
                        "version" => value[field] = serde_json::json!("1.2.4"),
                        "nanos" => value["remaining"]["nanos"] = serde_json::json!(1_000_000_000u64),
                        "nested_extra" => value["remaining"]["extra"] = serde_json::json!(true),
                        _ => value[field] = serde_json::json!(true),
                    }
                    bad.push(serde_json::to_vec(&value).unwrap());
                }
                for bytes in bad {
                    fs::write(&path, &bytes).unwrap();
                    assert!(read_receipt(&request).is_err());
                    assert!(observe(&request, &clock("a", 1000)).is_err());
                    assert_eq!(fs::read(&path).unwrap(), bytes);
                }
            }

            #[test]
            fn staging_first_receipt_requires_every_barrier_even_for_zero_delay() {
                for step in [BarrierStep::Write, BarrierStep::FileSync,
                    BarrierStep::Rename, BarrierStep::DirectorySync] {
                    let (_dir, mut request, _lock) = fixture();
                    request.window_minutes = 0;
                    assert!(observe_with_failure(&request, &clock("a", 1000), step).is_err());
                    // A complete visible record after failed directory sync is
                    // diagnostic, not an acknowledgement on a fresh attempt.
                    assert!(observe_with_failure(&request, &clock("a", 1000), step).is_err());
                    assert_eq!(observe(&request, &clock("a", 1000)).unwrap(), Decision::Due);
                }
            }

            #[test]
            fn staging_due_checkpoint_must_reacknowledge_barriers_after_failed_rename_sync() {
                for step in [BarrierStep::Write, BarrierStep::FileSync,
                    BarrierStep::Rename, BarrierStep::DirectorySync] {
                    let (_dir, request, _lock) = fixture();
                    observe(&request, &clock("a", 1000)).unwrap();
                    let path = receipt_path(&request).unwrap();
                    let before = fs::read(&path).unwrap();
                    assert!(observe_with_failure(&request, &clock("a", 2_533_000), step).is_err());
                    if !matches!(step, BarrierStep::DirectorySync) {
                        assert_eq!(fs::read(&path).unwrap(), before);
                    } else {
                        assert_eq!(read_receipt(&request).unwrap().unwrap().remaining, Duration::ZERO);
                    }
                    assert!(observe_with_failure(&request, &clock("a", 2_533_000), step).is_err());
                    assert_eq!(observe(&request, &clock("a", 2_533_000)).unwrap(), Decision::Due);
                    assert!(observe_with_failure(&request, &clock("a", 2_533_000), step).is_err());
                    assert_eq!(fs::read(&request.install).unwrap(), b"owned installed fixture");
                }
            }

            #[test]
            fn staging_large_delays_roundtrip_without_millisecond_overflow() {
                let (_dir, mut request, _lock) = fixture();
                request.window_minutes = u64::MAX;
                let chosen = Duration::from_secs(12_977_049_052_995_283_985);
                assert_eq!(observe(&request, &clock("a", 1000)).unwrap(), Decision::Waiting(chosen));
                let remaining = chosen - Duration::from_millis(500);
                assert_eq!(observe(&request, &clock("a", 1500)).unwrap(), Decision::Waiting(remaining));
                assert_eq!(read_receipt(&request).unwrap().unwrap().remaining, remaining);
                assert_eq!(observe(&request, &clock("b", 0)).unwrap(), Decision::Waiting(remaining));
            }
        }
    };
}
