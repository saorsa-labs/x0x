// Expanded in server::upgrade_flush. Exercises the real authenticated handler
// with offline state and owned producers; no socket, supervisor, or binary replacement.
#[allow(unused_macros)]
macro_rules! arm_flush_regression_tests {
    () => {
        #[cfg(test)]
        mod arm_flush_regressions {
            use super::*;
            use serde_json::{json, Value};
            use std::sync::atomic::{AtomicBool, Ordering};

            fn fixture() -> (tempfile::TempDir, Value, Value, ControlContext) {
                let base = std::env::var_os("X0X_UPGRADE_FLUSH_EVIDENCE_DIR").map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".planning/upgrade-flush-fixtures"));
                std::fs::create_dir_all(&base).unwrap();
                let dir = tempfile::Builder::new().prefix("arm-").tempdir_in(base).unwrap();
                let root = dir.path().canonicalize().unwrap();
                let executable = crate::upgrade::apply::current_binary_path().unwrap();
                let artifact = |name: &str, target: PathBuf| json!({
                    "target_path": target, "staged_path": root.join(format!("{name}.staged")),
                    "backup_path": root.join(format!("{name}.backup")),
                    "previous_sha256": vec![1_u8; 32], "candidate_sha256": vec![2_u8; 32],
                });
                let journal = json!({
                    "schema_version": 1, "record_kind": "journal", "sequence": 7,
                    "transaction_id": uuid::Uuid::new_v4().to_string(), "generation": 3,
                    "phase": "swapped_cli", "cause": null,
                    "daemon_progress": {"swapped": true, "restored": false, "observed_sha256": vec![2_u8; 32]},
                    "cli_progress": {"swapped": true, "restored": false, "observed_sha256": vec![2_u8; 32]},
                    "plan": {
                        "previous_version": "1.0.0", "candidate_version": "2.0.0", "manifest_sha256": vec![3_u8; 32],
                        "daemon": artifact("daemon", executable.clone()), "cli": artifact("cli", root.join("x0x")),
                        "participants": [{
                            "instance_id": "alice", "executable": executable, "data_root": root,
                            "identity_root": root, "cwd": root, "argv": ["x0xd"], "env": {},
                            "old_pid": std::process::id(), "process_start": process_start().unwrap(), "was_running": true,
                            "boot_id": crate::upgrade::probe::ProbeClock::now().unwrap().boot_id,
                            "restart": {"mode": "SupervisedExit", "supervised_exit_code": 75,
                                "supervision_signal": "fixture", "launchd_verified": null,
                                "systemd_verified": null, "launcher": null}
                        }]
                    }
                });
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                let request = json!({"token": "owned fixture credential", "instance_id": "alice",
                    "transaction_id": journal["transaction_id"], "generation": 3, "plan": journal["plan"]});
                let state = ControlContext { api_token: "owned fixture credential".into(),
                    api_address: "127.0.0.1:1".parse().unwrap(), identity_root: root };
                (dir, journal, request, state)
            }

            #[test]
            fn arm_flush_auth_and_frozen_binding_precede_the_actual_flush() {
                let (dir, journal, request, state) = fixture();
                let root = dir.path().canonicalize().unwrap();
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let counted = Arc::clone(&calls);
                let owner = shutdown_flush::register(root.clone(), Arc::new(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst); Ok(())
                })).unwrap();
                for (field, value) in [
                    ("token", json!("wrong credential")),
                    ("transaction_id", json!(uuid::Uuid::new_v4().to_string())),
                    ("generation", json!(4)), ("instance_id", json!("another participant")),
                    ("start_apply", json!(true)),
                ] {
                    let mut changed = request.clone(); changed[field] = value;
                    assert!(arm(&state, &root, &serde_json::to_vec(&changed).unwrap()).is_err(), "{field}");
                }
                let mut changed = request.clone(); changed["plan"]["candidate_version"] = json!("3.0.0");
                assert!(arm(&state, &root, &serde_json::to_vec(&changed).unwrap()).is_err());
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert!(!root.join(shutdown_flush::RECORD).exists());
                assert!(!root.join(journal::HANDOFF_FILE_NAME).exists());
                let receipt = arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap();
                owner.join_workers();
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let plan: journal::FrozenPlan = serde_json::from_value(journal["plan"].clone()).unwrap();
                let binding = shutdown_flush::Binding::new(request["transaction_id"].as_str().unwrap().into(),
                    3, &("alice", plan.clone())).unwrap();
                receipt.authorize(&binding).unwrap();
                let other = shutdown_flush::Binding::new(binding.transaction_id.clone(), 3, &("other", plan)).unwrap();
                assert!(receipt.authorize(&other).is_err());
                assert!(matches!(journal::read_boot_records(&root).handoff, journal::RecordRead::Handoff(_)));
                let saved: Value = serde_json::from_slice(&std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                assert!(saved["receipt_id"].as_str().is_some());
                assert_eq!(saved["binding"], serde_json::to_value(binding).unwrap());
            }

            #[test]
            fn arm_flush_refuses_a_different_old_process_even_in_a_matching_plan() {
                for (field, value) in [("old_pid", json!(u32::MAX)), ("boot_id", json!("different-boot")),
                    ("process_start", json!(0)), ("was_running", json!(false)),
                    ("data_root", json!("/")), ("identity_root", json!("/"))] {
                    let (dir, mut journal, mut request, state) = fixture();
                    let root = dir.path().canonicalize().unwrap();
                    journal["plan"]["participants"][0][field] = value;
                    request["plan"] = journal["plan"].clone();
                    journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                    let called = Arc::new(AtomicBool::new(false));
                    let observed = Arc::clone(&called);
                    let owner = shutdown_flush::register(root.clone(), Arc::new(move |_| {
                        observed.store(true, Ordering::SeqCst); Ok(())
                    })).unwrap();
                    assert!(arm(&state, &root, &serde_json::to_vec(&request).unwrap()).is_err());
                    owner.join_workers();
                    assert!(!called.load(Ordering::SeqCst));
                    assert!(!root.join(shutdown_flush::RECORD).exists());
                }
            }

            #[test]
            fn shutdown_state_barrier_refuses_symlinks_without_following_them() {
                let (dir, _, _, _) = fixture();
                std::fs::create_dir(dir.path().join("store")).unwrap();
                std::fs::write(dir.path().join("store/state"), b"accepted state").unwrap();
                sync_tree(dir.path()).unwrap();
                let target = dir.path().join("absent-target");
                std::os::unix::fs::symlink(&target, dir.path().join("store/link")).unwrap();
                assert!(sync_tree(dir.path()).is_err());
                assert!(!target.exists());
                assert_eq!(std::fs::read(dir.path().join("store/state")).unwrap(), b"accepted state");
            }


        }
    };
}
