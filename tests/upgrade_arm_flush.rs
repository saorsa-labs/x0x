// Expanded in server::upgrade_flush. Exercises the real authenticated handler
// with offline state and owned producers. The socket case requires Linux isolation.
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
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/upgrade-flush-fixtures"));
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
                let (dir, mut journal, mut request, state) = fixture();
                let root = dir.path().canonicalize().unwrap();
                journal["plan"]["participants"][0]["restart"]["mode"] = json!("TransactionalHandoff");
                request["plan"] = journal["plan"].clone();
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let counted = Arc::clone(&calls);
                let owner = shutdown_flush::register(root.clone(), Arc::new(move |_, _| {
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
                let mut unsupported = journal.clone();
                unsupported["plan"]["participants"][0]["restart"]["mode"] = json!("LauncherChild");
                unsupported["plan"]["participants"][0]["restart"]["launcher"] = json!({
                    "executable": root.join("launcher"), "argv": ["launcher"], "pid": null,
                    "process_start": null, "boot_id": "fixture-boot", "manager_exit_code": 0 });
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &unsupported).unwrap();
                let mut unsupported_request = request.clone(); unsupported_request["plan"] = unsupported["plan"].clone();
                assert_eq!(arm(&state, &root, &serde_json::to_vec(&unsupported_request).unwrap()).unwrap_err().kind(), io::ErrorKind::Unsupported);
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
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
                let journal::RecordRead::Handoff(handoff) = journal::read_boot_records(&root).handoff else { panic!("missing handoff") };
                assert_eq!(handoff.legacy["mode"], json!("TransactionalHandoff"));
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
                    let owner = shutdown_flush::register(root.clone(), Arc::new(move |_, _| {
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
                let deadline = shutdown_flush::Deadline::for_test(Duration::from_secs(5)).unwrap();
                sync_tree(dir.path(), &deadline).unwrap();
                let target = dir.path().join("absent-target");
                std::os::unix::fs::symlink(&target, dir.path().join("store/link")).unwrap();
                assert!(sync_tree(dir.path(), &deadline).is_err());
                assert!(!target.exists());
                assert_eq!(std::fs::read(dir.path().join("store/state")).unwrap(), b"accepted state");
            }

            #[test]
            fn flush_refusals_name_the_offending_path() {
                // Issue #1595: an operator-facing refusal must name the path
                // that caused it, or the operator cannot find the symlink to
                // remove. The walk refuses the link itself and any other
                // unsupported type (a FIFO) the same way.
                let (dir, _, _, _) = fixture();
                let store = dir.path().join("store");
                std::fs::create_dir_all(&store).unwrap();
                let link = store.join("link");
                std::os::unix::fs::symlink(dir.path().join("elsewhere"), &link).unwrap();
                let deadline = shutdown_flush::Deadline::for_test(Duration::from_secs(5)).unwrap();
                let refusal = sync_tree(dir.path(), &deadline).unwrap_err();
                assert!(refusal.to_string().contains("unverified symlink"), "{refusal}");
                assert!(refusal.to_string().contains(&link.display().to_string()), "{refusal}");
                std::fs::remove_file(&link).unwrap();
                let fifo = store.join("pipe");
                let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
                    .unwrap();
                // SAFETY: mkfifo only reads the passed path string and creates
                // the named pipe at it; the path is owned by this test.
                assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
                let refusal = sync_tree(dir.path(), &deadline).unwrap_err();
                assert!(refusal.to_string().contains("unsupported shutdown state file type"), "{refusal}");
                assert!(refusal.to_string().contains(&fifo.display().to_string()), "{refusal}");
            }

            #[test]
            fn arm_producers_only_started_failure_retries_before_the_hold() {
                // Issue #1595: the same bounded retry budget covers the
                // arm-and-flush path. A started failure caused only by
                // unfinished producers restores and classifies FlushFailed
                // on every attempt; the first budget failures write no
                // hold, so the exit-75 restart retries the release, and the
                // spent budget finally holds it.
                let mut carried: Option<Vec<u8>> = None;
                for attempt in 1..=(shutdown_flush::PRODUCER_DRAIN_RETRIES + 1) {
                    let (dir, _, request, state, cli, backup) = swapped_cli_fixture();
                    let root = dir.path().canonicalize().unwrap();
                    if let Some(prior) = &carried {
                        std::fs::write(root.join(shutdown_flush::RETRY_RECORD), prior).unwrap();
                    }
                    let owner = shutdown_flush::register(root.clone(), Arc::new(
                        |deadline, stopped| {
                            deadline.commit_stop(stopped)?;
                            Err(io::Error::other(shutdown_flush::PRODUCERS_UNFINISHED))
                        },
                    ))
                    .unwrap();
                    let failure =
                        arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap_err();
                    owner.join_workers();
                    assert!(matches!(failure, ArmFailure::FlushFailed(_)));
                    assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                    assert!(!backup.exists(), "the fresh backup is consumed by the restore");
                    assert_eq!(
                        root.join(shutdown_flush::HOLD_RECORD).exists(),
                        attempt > shutdown_flush::PRODUCER_DRAIN_RETRIES,
                        "attempt {attempt}"
                    );
                    carried = Some(std::fs::read(root.join(shutdown_flush::RETRY_RECORD)).unwrap());
                }
            }

            #[test]
            fn arm_started_failure_from_a_refused_symlink_holds_and_restores() {
                // Issue #1595 item 1: a flush failure forced by a symlink
                // under the data root is a started failure — the daemon
                // stopped behind the hook — so it must end in the restore,
                // the per-release hold and the EX_TEMPFAIL classification,
                // never a plain refusal.
                let (dir, _, request, state, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let link = root.join("store-link");
                std::os::unix::fs::symlink(root.join("elsewhere"), &link).unwrap();
                let walk_root = root.clone();
                let owner = shutdown_flush::register(root.clone(), Arc::new(
                    move |deadline, stopped| {
                        deadline.commit_stop(stopped)?;
                        sync_tree(&walk_root, &deadline)
                    },
                ))
                .unwrap();
                let failure = arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap_err();
                owner.join_workers();
                assert!(matches!(failure, ArmFailure::FlushFailed(_)));
                assert!(failure.to_string().contains("unverified symlink"), "{failure}");
                assert!(failure.to_string().contains(&link.display().to_string()), "{failure}");
                assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                assert!(!backup.exists());
                assert!(root.join(shutdown_flush::ROLLBACK_RECORD).is_file());
                assert!(root.join(shutdown_flush::HOLD_RECORD).is_file());
            }

            #[test]
            fn admission_preflight_names_the_offending_symlink() {
                // Issue #1595: the same refusal must surface before an
                // upgrade is attempted — at flush admission, before any
                // byte changes — naming the path.
                let (dir, _, _, _) = fixture();
                let root = dir.path().canonicalize().unwrap();
                std::fs::create_dir_all(root.join("store")).unwrap();
                let link = root.join("store/link");
                std::os::unix::fs::symlink(root.join("elsewhere"), &link).unwrap();
                let scan_roots = vec![root.clone()];
                let owner = shutdown_flush::register_with_preflight(
                    root.clone(),
                    Arc::new(|_, _| Ok(())),
                    Arc::new(move || scan_flush_state(&scan_roots)),
                )
                .unwrap();
                let refusal = shutdown_flush::ensure_ready(&root).unwrap_err();
                assert!(refusal.to_string().contains("cannot be flushed"), "{refusal}");
                assert!(refusal.to_string().contains("unverified symlink"), "{refusal}");
                assert!(refusal.to_string().contains(&link.display().to_string()), "{refusal}");
                drop(owner);
            }

            #[test]
            fn admission_preflight_accepts_a_clean_tree_and_the_control_socket() {
                // The daemon's own control socket lives under the data root;
                // the admission walk must accept it exactly as the flush does,
                // and a clean tree must not refuse the next upgrade.
                let (dir, _, _, _) = fixture();
                let root = dir.path().canonicalize().unwrap();
                std::fs::create_dir_all(root.join("store")).unwrap();
                std::fs::write(root.join("store/state"), b"state").unwrap();
                let socket = root.join(SOCKET);
                std::os::unix::net::UnixListener::bind(&socket).unwrap();
                let scan_roots = vec![root.clone()];
                let owner = shutdown_flush::register_with_preflight(
                    root.clone(),
                    Arc::new(|_, _| Ok(())),
                    Arc::new(move || scan_flush_state(&scan_roots)),
                )
                .unwrap();
                shutdown_flush::ensure_ready(&root).unwrap();
                drop(owner);
            }

            #[test]
            fn shutdown_state_barrier_stops_after_a_sync_returns_past_the_deadline() {
                let (dir, _, _, _) = fixture();
                let root = dir.path().canonicalize().unwrap();
                let store = root.join("store");
                std::fs::create_dir(&store).unwrap();
                for name in ["first", "second"] { std::fs::write(store.join(name), b"state").unwrap(); }
                let deadline = shutdown_flush::Deadline::for_test(Duration::from_secs(5)).unwrap();
                let mut control = 0;
                sync_tree_with(&store, &deadline, &mut |_| { control += 1; Ok(()) }).unwrap();
                assert_eq!(control, 3);
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let counted = Arc::clone(&calls);
                let (entered, entering) = mpsc::channel();
                let (release, released) = mpsc::channel();
                let released = Mutex::new(released);
                let owner = shutdown_flush::register_with_limit(root.clone(), Arc::new(move |deadline, _| {
                    sync_tree_with(&store, &deadline, &mut |_| {
                        if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                            let _ = entered.send(());
                            released.lock().unwrap().recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                        }
                        Ok(())
                    })
                }), Duration::from_secs(2)).unwrap();
                let binding = shutdown_flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                let (returned, result) = mpsc::channel();
                let caller = std::thread::spawn(move || {
                    let _ = returned.send(shutdown_flush::acknowledge(&root, binding, || Ok(())));
                });
                let did_enter = entering.recv_timeout(Duration::from_secs(5));
                let outcome = result.recv_timeout(Duration::from_secs(5));
                let _ = release.send(());
                caller.join().unwrap();
                owner.join_workers();
                did_enter.unwrap();
                assert_eq!(outcome.unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
                assert_eq!(calls.load(Ordering::SeqCst), 1, "no new sync after expiry");
            }

            #[test]
            fn arm_flush_failure_reports_the_started_failure_and_marks_the_upgrade() {
                let (dir, journal, request, state) = fixture();
                let root = dir.path().canonicalize().unwrap();
                // The frozen plan's daemon target is pinned to the running
                // executable by the journal's participant/install consistency
                // rule, so daemon byte restoration is proven at the trigger
                // level (supervised_exit_after_failed_flush_restores_the_previous_binary).
                // Here the journal says both artifacts swapped, the CLI has a
                // backup, and the daemon's backup is absent: the
                // both-or-neither rule must restore neither.
                let target: PathBuf =
                    serde_json::from_value(journal["plan"]["daemon"]["target_path"].clone())
                        .unwrap();
                let cli: PathBuf =
                    serde_json::from_value(journal["plan"]["cli"]["target_path"].clone()).unwrap();
                let cli_backup: PathBuf =
                    serde_json::from_value(journal["plan"]["cli"]["backup_path"].clone()).unwrap();
                std::fs::write(&cli, b"swapped candidate cli").unwrap();
                std::fs::write(&cli_backup, b"previous cli").unwrap();
                let before = std::fs::read(&target).unwrap();
                let owner = shutdown_flush::register(root.clone(), Arc::new(|_, stopped| {
                    stopped.store(true, Ordering::SeqCst);
                    Err(io::Error::other("injected started flush failure"))
                }))
                .unwrap();
                let failure = arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap_err();
                owner.join_workers();
                // Engineer ruling 23 Oct 2026: a flush that started and the
                // daemon stopped behind is a FlushFailed (the process exits
                // EX_TEMPFAIL for a restart on the old version), never a
                // plain refusal.
                assert!(matches!(failure, ArmFailure::FlushFailed(_)));
                assert_eq!(std::fs::read(&target).unwrap(), before);
                // Missing daemon backup ⇒ neither artifact is restored.
                assert_eq!(std::fs::read(&cli).unwrap(), b"swapped candidate cli");
                assert!(root.join(shutdown_flush::ROLLBACK_RECORD).is_file());
                // The failed release is held; the retry loop is broken.
                let hold: Value = serde_json::from_slice(
                    &std::fs::read(root.join(shutdown_flush::HOLD_RECORD)).unwrap()).unwrap();
                assert_eq!(hold["record_kind"], json!("shutdown_flush_hold"));
                assert_eq!(hold["held_version"], journal["plan"]["candidate_version"]);
                let saved: Value = serde_json::from_slice(
                    &std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                assert!(saved["receipt_id"].is_null());
            }

            #[test]
            fn arm_flush_refusal_before_the_daemon_stops_restores_and_holds_nothing() {
                let (dir, journal, request, state) = fixture();
                let root = dir.path().canonicalize().unwrap();
                let cli: PathBuf =
                    serde_json::from_value(journal["plan"]["cli"]["target_path"].clone()).unwrap();
                std::fs::write(&cli, b"swapped candidate cli").unwrap();
                // The hook fails before the daemon stops behind it: an
                // ordinary refusal keeps the daemon serving (engineer ruling,
                // 23 Oct 2026). The daemon's backup is absent, so the
                // both-or-neither rule restores neither artifact.
                let owner = shutdown_flush::register(root.clone(), Arc::new(|_, _| {
                    Err(io::Error::other("injected refusal before the stop"))
                }))
                .unwrap();
                let failure = arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap_err();
                owner.join_workers();
                assert!(matches!(failure, ArmFailure::Refused(_)));
                assert_eq!(std::fs::read(&cli).unwrap(), b"swapped candidate cli");
                assert!(!root.join(shutdown_flush::HOLD_RECORD).exists());
                assert!(!root.join(shutdown_flush::ROLLBACK_RECORD).exists());
            }

            #[test]
            fn arm_flush_refusal_before_the_daemon_stops_restores_the_swapped_artifacts() {
                // Engineer ruling, 24 Oct 2026: a refusal is not a failed
                // start. The daemon keeps serving, so the artifacts this
                // frozen transaction swapped go back from their verified
                // backups. The journal here swapped only the CLI, so the
                // daemon (the running test executable) stays untouched.
                let (dir, mut journal, mut request, state) = fixture();
                let root = dir.path().canonicalize().unwrap();
                journal["daemon_progress"]["swapped"] = json!(false);
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                request["plan"] = journal["plan"].clone();
                let cli: PathBuf =
                    serde_json::from_value(journal["plan"]["cli"]["target_path"].clone()).unwrap();
                let cli_backup: PathBuf =
                    serde_json::from_value(journal["plan"]["cli"]["backup_path"].clone()).unwrap();
                std::fs::write(&cli, b"swapped candidate cli").unwrap();
                std::fs::write(&cli_backup, b"previous cli").unwrap();
                let owner = shutdown_flush::register(root.clone(), Arc::new(|_, _| {
                    Err(io::Error::other("injected refusal before the stop"))
                }))
                .unwrap();
                let failure = arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap_err();
                owner.join_workers();
                assert!(matches!(failure, ArmFailure::Refused(_)));
                assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                assert!(!cli_backup.exists(), "the fresh backup is consumed by the restore");
                assert!(!root.join(shutdown_flush::HOLD_RECORD).exists());
                assert!(!root.join(shutdown_flush::ROLLBACK_RECORD).exists());
                // Admission re-opens for a later supervised apply: the
                // refused attempt cleared its own intent record.
                assert!(!root.join(shutdown_flush::RECORD).exists());
                shutdown_flush::ensure_ready(&root).unwrap();
            }

            // Only the CLI fixture is swapped: the daemon is this test executable.
            fn swapped_cli_fixture() -> (tempfile::TempDir, Value, Value, ControlContext, PathBuf, PathBuf) {
                let (dir, mut record, request, state) = fixture();
                record["daemon_progress"]["swapped"] = json!(false);
                journal::write_record(&dir.path().join(journal::JOURNAL_FILE_NAME), &record).unwrap();
                let cli: PathBuf = serde_json::from_value(record["plan"]["cli"]["target_path"].clone()).unwrap();
                let backup: PathBuf = serde_json::from_value(record["plan"]["cli"]["backup_path"].clone()).unwrap();
                std::fs::write(&cli, b"candidate cli").unwrap();
                std::fs::write(&backup, b"previous cli").unwrap();
                (dir, record, request, state, cli, backup)
            }

            #[test]
            fn arm_started_failure_archives_restored_journal_and_allows_newer_release() {
                let (dir, original, request, state, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let owner = shutdown_flush::register(root.clone(), Arc::new(|deadline, stopped| {
                    deadline.commit_stop(stopped)?;
                    Err(io::Error::other("injected started flush failure"))
                })).unwrap();
                assert!(matches!(arm(&state, &root, &serde_json::to_vec(&request).unwrap()),
                    Err(ArmFailure::FlushFailed(_))));
                owner.join_workers();
                assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                assert!(!backup.exists());
                assert!(!root.join(journal::HANDOFF_FILE_NAME).exists(), "resolved handoff must be removed");
                assert!(!journal::read_boot_records(&root).blocks_apply(), "resolved journal must not block newer releases");
                let archives: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().path())
                    .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("upgrade-failed-")).collect();
                assert_eq!(archives.len(), 1);
                let saved: Value = serde_json::from_slice(&std::fs::read(&archives[0]).unwrap()).unwrap();
                assert_eq!(saved["sequence"], original["sequence"].as_u64().unwrap() + 2);
                assert_eq!(saved["phase"], "restored");
                assert_eq!(saved["cause"]["class"], "failed");
                assert!(saved["cause"]["reason"].as_str().unwrap().contains("flush failure"));
                assert_eq!(saved["cli_progress"]["swapped"], false);
                assert_eq!(saved["cli_progress"]["restored"], true);
                assert!(saved["cli_progress"]["observed_sha256"].is_null());
                assert_eq!(saved["daemon_progress"], original["daemon_progress"]);
                assert!(shutdown_flush::release_is_held(&root, &semver::Version::new(2, 0, 0)).unwrap().is_some());
                assert!(shutdown_flush::release_is_held(&root, &semver::Version::new(1, 0, 0)).unwrap().is_some());
                // Model the exit-75 restart: stale receipt-less flush records
                // clear, the per-release hold stays, and new admission opens.
                let restarted_root = root.join("restart-records");
                std::fs::create_dir(&restarted_root).unwrap();
                for name in [shutdown_flush::RECORD, shutdown_flush::ROLLBACK_RECORD, shutdown_flush::HOLD_RECORD] {
                    std::fs::copy(root.join(name), restarted_root.join(name)).unwrap();
                }
                shutdown_flush::clear_stale_records(&restarted_root);
                let _restarted = shutdown_flush::register(restarted_root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
                assert!(restarted_root.join(shutdown_flush::HOLD_RECORD).is_file());
                assert!(!journal::read_boot_records(&root).blocks_apply());
                assert!(shutdown_flush::release_is_held(&restarted_root, &semver::Version::new(2, 0, 1)).unwrap().is_none());
                shutdown_flush::ensure_ready(&restarted_root).unwrap();
                shutdown_flush::reserve(&restarted_root).unwrap().activate().unwrap();
            }

            #[test]
            fn arm_started_partial_restore_keeps_rolling_back_and_blocks_apply() {
                let (dir, mut record, request, state, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let handoff = admit(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap().handoff;
                let daemon = root.join("owned-daemon");
                let daemon_backup = root.join("daemon.backup");
                std::fs::write(&daemon, b"candidate daemon").unwrap();
                std::fs::write(&daemon_backup, b"previous daemon").unwrap();
                record["daemon_progress"]["swapped"] = json!(true);
                record["plan"]["daemon"]["target_path"] = json!(daemon);
                record["plan"]["participants"][0]["executable"] = json!(daemon);
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
                // Both backups are valid. The second rename fails after the
                // daemon rename succeeded, leaving a mixed pair for recovery.
                std::fs::remove_file(&cli).unwrap();
                std::fs::create_dir(&cli).unwrap();
                journal::write_record(&root.join(journal::HANDOFF_FILE_NAME), &handoff).unwrap();
                let restore = vec![(daemon.clone(), daemon_backup), (cli, backup)];
                let outcome = restore_arm(&root, serde_json::from_value(record).unwrap(),
                    &handoff, true, &restore, journal::Cause {
                        class: journal::CauseClass::Failed, reason: "shutdown flush failure".into(),
                    });
                assert!(outcome.is_err());
                assert_eq!(std::fs::read(&daemon).unwrap(), b"previous daemon");
                let saved: Value = serde_json::from_slice(&std::fs::read(root.join(journal::JOURNAL_FILE_NAME)).unwrap()).unwrap();
                assert_eq!(saved["phase"], "rolling_back");
                assert_eq!(saved["cause"]["class"], "failed");
                assert!(root.join(journal::HANDOFF_FILE_NAME).exists());
                assert!(journal::read_boot_records(&root).blocks_apply());
            }

            #[test]
            fn arm_duplicate_after_receipt_preserves_installed_bytes_and_receipt() {
                let (dir, _, request, state, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let owner = shutdown_flush::register(root.clone(), Arc::new(|_, stopped| {
                    stopped.store(true, Ordering::Release);
                    Ok(())
                })).unwrap();
                let request = serde_json::to_vec(&request).unwrap();
                arm(&state, &root, &request).unwrap();
                owner.join_workers();
                let paths = [shutdown_flush::RECORD, journal::HANDOFF_FILE_NAME, journal::JOURNAL_FILE_NAME];
                let before: Vec<_> = paths.iter().map(|path| std::fs::read(root.join(path)).unwrap()).collect();
                let failure = arm(&state, &root, &request).unwrap_err();
                assert!(matches!(failure, ArmFailure::Refused(_)));
                assert_eq!(std::fs::read(&cli).unwrap(), b"candidate cli");
                assert_eq!(std::fs::read(&backup).unwrap(), b"previous cli");
                for (path, bytes) in paths.iter().zip(before) {
                    assert_eq!(std::fs::read(root.join(path)).unwrap(), bytes);
                }
                assert!(shutdown_flush::reserve(&root).is_err());
            }

            #[test]
            fn arm_collision_with_auto_apply_reservation_preserves_the_winner() {
                let (dir, _, request, state, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let owner = shutdown_flush::register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
                let reservation = shutdown_flush::reserve(&root).unwrap();
                reservation.activate().unwrap();
                let request = serde_json::to_vec(&request).unwrap();
                let failure = arm(&state, &root, &request).unwrap_err();
                assert!(matches!(failure, ArmFailure::Refused(_)));
                assert_eq!(std::fs::read(&cli).unwrap(), b"candidate cli");
                assert_eq!(std::fs::read(&backup).unwrap(), b"previous cli");
                assert!(shutdown_flush::reserve(&root).is_err());
                assert!(!root.join(journal::HANDOFF_FILE_NAME).exists());
                let binding = shutdown_flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"auto apply").unwrap();
                shutdown_flush::acknowledge_reserved(&root, binding, || Ok(()), &reservation).unwrap();
                owner.join_workers();
            }

            #[test]
            fn arm_owned_refusal_rewinds_journal_and_cannot_receipt_restored_bytes() {
                let (dir, _, request, state, cli, _) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let first = AtomicBool::new(true);
                let owner = shutdown_flush::register(root.clone(), Arc::new(move |_, _| {
                    if first.swap(false, Ordering::SeqCst) {
                        Err(io::Error::other("injected refusal"))
                    } else { Ok(()) }
                })).unwrap();
                let request = serde_json::to_vec(&request).unwrap();
                assert!(matches!(arm(&state, &root, &request), Err(ArmFailure::Refused(_))));
                owner.join_workers();
                assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                assert!(arm(&state, &root, &request).is_err(), "the old plan must not receipt restored bytes");
                owner.join_workers();
                assert!(!root.join(shutdown_flush::RECORD).exists());
                assert!(!root.join(journal::HANDOFF_FILE_NAME).exists());
                assert!(!journal::read_boot_records(&root).blocks_apply());
                let archives: Vec<_> = std::fs::read_dir(&root).unwrap().map(|entry| entry.unwrap().path())
                    .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with("upgrade-refused-")).collect();
                assert_eq!(archives.len(), 1);
                let saved: Value = serde_json::from_slice(&std::fs::read(&archives[0]).unwrap()).unwrap();
                assert_eq!(saved["phase"], "restored");
                assert_eq!(saved["cli_progress"]["swapped"], false);
                assert_eq!(saved["cli_progress"]["restored"], true);
                assert_eq!(saved["daemon_progress"]["swapped"], false);
                shutdown_flush::ensure_ready(&root).unwrap();
                let reservation = shutdown_flush::reserve(&root).unwrap();
                reservation.activate().unwrap();
            }

            #[test]
            fn arm_without_owner_preserves_swapped_bytes_and_journal() {
                let (dir, _, request, state, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let before = std::fs::read(root.join(journal::JOURNAL_FILE_NAME)).unwrap();
                assert!(arm(&state, &root, &serde_json::to_vec(&request).unwrap()).is_err());
                assert_eq!(std::fs::read(&cli).unwrap(), b"candidate cli");
                assert_eq!(std::fs::read(&backup).unwrap(), b"previous cli");
                assert_eq!(std::fs::read(root.join(journal::JOURNAL_FILE_NAME)).unwrap(), before);
            }

            #[test]
            fn arm_owned_refusal_preserves_a_preexisting_handoff() {
                let (dir, _, request, state, cli, _) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let request = serde_json::to_vec(&request).unwrap();
                let handoff = admit(&state, &root, &request).unwrap().handoff;
                let path = root.join(journal::HANDOFF_FILE_NAME);
                journal::write_record(&path, &handoff).unwrap();
                let before = std::fs::read(&path).unwrap();
                let owner = shutdown_flush::register(root.clone(), Arc::new(|_, _| panic!("existing handoff refuses prepare"))).unwrap();
                assert!(arm(&state, &root, &request).is_err());
                owner.join_workers();
                assert_eq!(std::fs::read(&path).unwrap(), before);
                assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                assert!(journal::read_boot_records(&root).blocks_apply());
                assert!(arm(&state, &root, &request).is_err());
            }

            // Socket execution belongs to the isolated Linux CI runner.
            #[cfg_attr(not(target_os = "linux"), ignore = "requires isolated Linux network namespace")]
            #[tokio::test]
            async fn arm_flush_unix_transport_receipts_only_after_the_real_shutdown_hook() {
                use std::io::Write;
                use tracing_subscriber::prelude::*;
                struct Sink { bytes: Arc<Mutex<Vec<u8>>>, fail: bool }
                impl Write for Sink {
                    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                        self.bytes.lock().unwrap().extend_from_slice(bytes); Ok(bytes.len())
                    }
                    fn flush(&mut self) -> io::Result<()> {
                        if self.fail { Err(io::Error::other("injected log barrier failure")) } else { Ok(()) }
                    }
                }
                for fail in [false, true] {
                    let (dir, _, mut request, _, cli, backup) = swapped_cli_fixture();
                    let root = dir.path().canonicalize().unwrap();
                    let agent = Arc::new(crate::Agent::builder()
                        .with_identity_dir(&root).with_user_key_path(root.join("user.key"))
                        .with_machine_key(root.join("machine.key"))
                        .with_agent_key_path(root.join("agent.key"))
                        .with_agent_cert_path(root.join("agent.cert"))
                        .with_contact_store_path(root.join("contacts.json"))
                        .with_peer_cache_disabled().build().await.unwrap());
                    assert!(agent.network().is_none());
                    let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                        &root, Arc::clone(&agent)).await.unwrap();
                    let mut notified = state.shutdown_notify.subscribe();
                    request["token"] = json!(state.api_token);
                    let bytes = Arc::new(Mutex::new(Vec::new()));
                    let (mut writer, mut guard) = log_flush::acknowledged(Sink { bytes: Arc::clone(&bytes), fail }).unwrap();
                    writer.write_all(b"accepted shutdown log").unwrap();
                    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry()
                        .with(log_flush::FlushLayer::new(vec![writer]).unwrap()));
                    let exit_code = Arc::new(std::sync::atomic::AtomicI32::new(-1));
                    let observed_exit = Arc::clone(&exit_code);
                    let mut owner = tracing::dispatcher::with_default(&dispatch,
                        || FlushOwner::start(&state, &root, &root,
                            Arc::new(move |code| observed_exit.store(code, std::sync::atomic::Ordering::SeqCst))))
                        .unwrap();
                    let mut stream = tokio::net::UnixStream::connect(root.join(SOCKET)).await.unwrap();
                    let mut encoded = serde_json::to_vec(&request).unwrap(); encoded.push(b'\n');
                    stream.write_all(&encoded).await.unwrap();
                    tokio::time::timeout(Duration::from_secs(5), notified.changed()).await.unwrap().unwrap();
                    assert!(*notified.borrow());
                    let pending: Value = serde_json::from_slice(&std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                    assert!(pending["receipt_id"].is_null());
                    state.exec_service.shutdown().await;
                    let producers = crate::server::drain_server_tasks(&state, Vec::new()).await;
                    let shutdown = agent.try_shutdown().await.map_err(anyhow::Error::from);
                    let cancel = tokio_util::sync::CancellationToken::new();
                    let reply = async {
                        let mut response = String::new();
                        let read = tokio::time::timeout(Duration::from_secs(5),
                            tokio::io::BufReader::new(stream).read_line(&mut response)).await;
                        read.unwrap().unwrap();
                        let response = serde_json::from_str::<Value>(&response).unwrap();
                        if !fail {
                            let receipt = std::fs::read(root.join(shutdown_flush::RECORD)).unwrap();
                            let mut retry = tokio::net::UnixStream::connect(root.join(SOCKET)).await.unwrap();
                            retry.write_all(&encoded).await.unwrap();
                            let mut duplicate = String::new();
                            tokio::time::timeout(Duration::from_secs(5),
                                tokio::io::BufReader::new(retry).read_line(&mut duplicate)).await.unwrap().unwrap();
                            let duplicate: Value = serde_json::from_str(&duplicate).unwrap();
                            assert!(duplicate["error"].is_string());
                            assert_eq!(std::fs::read(&cli).unwrap(), b"candidate cli");
                            assert_eq!(std::fs::read(&backup).unwrap(), b"previous cli");
                            assert_eq!(std::fs::read(root.join(shutdown_flush::RECORD)).unwrap(), receipt);
                        }
                        cancel.cancel();
                        response
                    };
                    let (response, ()) = tokio::join!(reply, owner.finish(&shutdown, producers, &cancel));
                    owner._registration.join_workers();
                    owner.control.abort(); let _ = (&mut owner.control).await;
                    let saved: Value = serde_json::from_slice(&std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                    assert_eq!(*bytes.lock().unwrap(), b"accepted shutdown log");
                    if fail {
                        assert!(response.get("receipt").is_none()); assert!(response["error"].is_string());
                        assert!(saved["receipt_id"].is_null());
                        // Engineer ruling 23 Oct 2026: a started flush that failed
                        // ends the process with EX_TEMPFAIL instead of parking the
                        // daemon with no API and no network.
                        assert_eq!(
                            exit_code.load(std::sync::atomic::Ordering::SeqCst),
                            crate::upgrade::restart::flush_failure_exit_code()
                        );
                    } else {
                        assert_eq!(response["receipt"]["receipt_id"], saved["receipt_id"]);
                        assert!(saved["receipt_id"].is_string());
                        assert_eq!(response["receipt"]["binding"], saved["binding"]);
                        assert_eq!(saved["binding"]["transaction_id"], request["transaction_id"]);
                        assert_eq!(saved["binding"]["generation"], request["generation"]);
                    }
                    let _ = guard.shutdown_until(Instant::now() + Duration::from_secs(1));
                }
            }

            // Socket execution belongs to the isolated Linux CI runner.
            #[cfg_attr(not(target_os = "linux"), ignore = "requires isolated Linux network namespace")]
            #[tokio::test]
            async fn arm_symlink_started_failure_exits_tempfail_without_the_shutdown_tail() {
                // Issue #1595 / Claude #1566 finding 1: the EX_TEMPFAIL exit
                // after a failed started flush must not depend on the server
                // shutdown tail reaching `finish` — a hung Agent shutdown
                // must not park the stopped daemon forever. A symlink under
                // the data root forces exactly that failure; the receipt a
                // finished tail would send is supplied by hand and `finish`
                // is never called.
                use std::io::Write;
                use tracing_subscriber::prelude::*;
                struct Sink;
                impl Write for Sink {
                    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                        Ok(bytes.len())
                    }
                    fn flush(&mut self) -> io::Result<()> {
                        Ok(())
                    }
                }
                let (dir, _, mut request, _, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                let link = root.join("store-link");
                std::os::unix::fs::symlink(root.join("elsewhere"), &link).unwrap();
                let agent = Arc::new(crate::Agent::builder()
                    .with_identity_dir(&root).with_user_key_path(root.join("user.key"))
                    .with_machine_key(root.join("machine.key"))
                    .with_agent_key_path(root.join("agent.key"))
                    .with_agent_cert_path(root.join("agent.cert"))
                    .with_contact_store_path(root.join("contacts.json"))
                    .with_peer_cache_disabled().build().await.unwrap());
                assert!(agent.network().is_none());
                let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                    &root, Arc::clone(&agent)).await.unwrap();
                let mut notified = state.shutdown_notify.subscribe();
                request["token"] = json!(state.api_token);
                let (writer, mut guard) = log_flush::acknowledged(Sink).unwrap();
                let dispatch = tracing::Dispatch::new(tracing_subscriber::registry()
                    .with(log_flush::FlushLayer::new(vec![writer]).unwrap()));
                let exit_code = Arc::new(std::sync::atomic::AtomicI32::new(-1));
                let observed_exit = Arc::clone(&exit_code);
                let mut owner = tracing::dispatcher::with_default(&dispatch,
                    || FlushOwner::start(&state, &root, &root,
                        Arc::new(move |code| observed_exit.store(code, std::sync::atomic::Ordering::SeqCst))))
                    .unwrap();
                let mut stream = tokio::net::UnixStream::connect(root.join(SOCKET)).await.unwrap();
                let mut encoded = serde_json::to_vec(&request).unwrap(); encoded.push(b'\n');
                stream.write_all(&encoded).await.unwrap();
                // The hook committed the stop; hand it the receipt a finished
                // shutdown tail would have sent, then let the walk refuse the
                // symlink exactly as in production.
                tokio::time::timeout(Duration::from_secs(5), notified.changed()).await.unwrap().unwrap();
                owner.complete.try_send(Ok(())).unwrap();
                let mut response = String::new();
                tokio::time::timeout(Duration::from_secs(5),
                    tokio::io::BufReader::new(&mut stream).read_line(&mut response))
                    .await.unwrap().unwrap();
                let response: Value = serde_json::from_str(&response).unwrap();
                let error = response["error"].as_str().unwrap();
                assert!(error.contains("unverified symlink in shutdown state"), "{error}");
                assert!(error.contains(&link.display().to_string()), "{error}");
                // The exit follows the reply from the control loop itself.
                let deadline = Instant::now() + Duration::from_secs(5);
                while exit_code.load(std::sync::atomic::Ordering::SeqCst) == -1
                    && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert_eq!(
                    exit_code.load(std::sync::atomic::Ordering::SeqCst),
                    crate::upgrade::restart::flush_failure_exit_code(),
                    "a failed started flush must exit without the shutdown tail"
                );
                // Recovery completed before the exit: the old bytes are back,
                // the release is held and the journal no longer blocks apply.
                assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                assert!(!backup.exists());
                assert!(root.join(shutdown_flush::HOLD_RECORD).is_file());
                assert!(!journal::read_boot_records(&root).blocks_apply());
                owner.control.abort(); let _ = (&mut owner.control).await;
                state.exec_service.shutdown().await;
                agent.try_shutdown().await.unwrap();
                let _ = guard.shutdown_until(Instant::now() + Duration::from_secs(1));
            }

            // #1665: use the production socket, owner, durability hook and
            // restart callback. No external supervisor or candidate is started.
            async fn socket_success_completion(mode: &str, lost_requester: bool, parked_tail: bool) {
                use std::io::Write;
                use tracing_subscriber::prelude::*;
                struct Sink;
                impl Write for Sink {
                    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { Ok(bytes.len()) }
                    fn flush(&mut self) -> io::Result<()> { Ok(()) }
                }
                let (dir, mut record, mut request, _, cli, backup) = swapped_cli_fixture();
                let root = dir.path().canonicalize().unwrap();
                // An injected status distinct from both the clean-stop default
                // and failure status proves the frozen supervisor value is used.
                record["plan"]["participants"][0]["restart"]["mode"] = json!(mode);
                record["plan"]["participants"][0]["restart"]["supervised_exit_code"] = json!(42);
                request["plan"] = record["plan"].clone();
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &record).unwrap();
                let agent = Arc::new(crate::Agent::builder()
                    .with_identity_dir(&root).with_user_key_path(root.join("user.key"))
                    .with_machine_key(root.join("machine.key"))
                    .with_agent_key_path(root.join("agent.key"))
                    .with_agent_cert_path(root.join("agent.cert"))
                    .with_contact_store_path(root.join("contacts.json"))
                    .with_peer_cache_disabled().build().await.unwrap());
                assert!(agent.network().is_none());
                let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                    &root, Arc::clone(&agent)).await.unwrap();
                let mut stopped = state.shutdown_notify.subscribe();
                request["token"] = json!(state.api_token);
                let (writer, mut guard) = log_flush::acknowledged(Sink).unwrap();
                let dispatch = tracing::Dispatch::new(tracing_subscriber::registry()
                    .with(log_flush::FlushLayer::new(vec![writer]).unwrap()));
                let (exit_tx, mut exit_rx) = tokio::sync::watch::channel(-1);
                let exit_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let counted = Arc::clone(&exit_calls);
                let mut owner = tracing::dispatcher::with_default(&dispatch,
                    || FlushOwner::start(&state, &root, &root, Arc::new(move |code| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = exit_tx.send(code);
                    }))).unwrap();

                // A valid credential with the wrong generation must neither
                // stop the participant nor obtain completion authority.
                let mut stale = request.clone(); stale["generation"] = json!(4);
                let mut rejected = tokio::net::UnixStream::connect(root.join(SOCKET)).await.unwrap();
                let mut bytes = serde_json::to_vec(&stale).unwrap(); bytes.push(b'\n');
                rejected.write_all(&bytes).await.unwrap();
                let mut refusal = String::new();
                tokio::time::timeout(Duration::from_secs(5),
                    tokio::io::BufReader::new(rejected).read_line(&mut refusal))
                    .await.unwrap().unwrap();
                assert!(serde_json::from_str::<Value>(&refusal).unwrap()["error"].is_string());
                assert!(!*stopped.borrow());
                assert!(!root.join(shutdown_flush::RECORD).exists());
                assert_eq!(exit_calls.load(Ordering::SeqCst), 0);

                let mut stream = tokio::net::UnixStream::connect(root.join(SOCKET)).await.unwrap();
                let mut bytes = serde_json::to_vec(&request).unwrap(); bytes.push(b'\n');
                stream.write_all(&bytes).await.unwrap();
                tokio::time::timeout(Duration::from_secs(5), stopped.changed()).await.unwrap().unwrap();
                assert!(*stopped.borrow());
                let mut stream = if lost_requester { drop(stream); None } else { Some(stream) };
                state.exec_service.shutdown().await;
                let producers = crate::server::drain_server_tasks(&state, Vec::new()).await;
                let shutdown = agent.try_shutdown().await.map_err(anyhow::Error::from);
                assert!(producers); assert!(shutdown.is_ok());
                let cancel = tokio_util::sync::CancellationToken::new();
                let observe = async {
                    if let Some(stream) = stream.as_mut() {
                        let mut reply = String::new();
                        tokio::time::timeout(Duration::from_secs(5),
                            tokio::io::BufReader::new(stream).read_line(&mut reply)).await.unwrap().unwrap();
                        let reply: Value = serde_json::from_str(&reply).unwrap();
                        let durable: Value = serde_json::from_slice(
                            &std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                        assert_eq!(reply["receipt"]["receipt_id"], durable["receipt_id"]);
                        assert!(durable["receipt_id"].is_string());
                        assert_eq!(reply["receipt"]["binding"], durable["binding"]);
                    }
                    let completion = tokio::time::timeout(Duration::from_secs(5), exit_rx.changed()).await;
                    // Cleanup cancellation must not be what causes the exit.
                    let code = *exit_rx.borrow();
                    let completed = completion.is_ok_and(|result| result.is_ok());
                    cancel.cancel();
                    (completed, code)
                };
                let (completed, code) = if parked_tail {
                    // `finish` publishes the real producer result, then parks.
                    tokio::join!(observe, owner.finish(&shutdown, producers, &cancel)).0
                } else {
                    // The producers really finished above. Publish their result
                    // but never enter `finish`: the control loop must not depend
                    // on a tail wakeup, even when its requester disappeared.
                    owner.complete.try_send(Ok(())).unwrap();
                    observe.await
                };
                owner._registration.join_workers();
                owner.control.abort(); let _ = (&mut owner.control).await;
                let durable: Value = serde_json::from_slice(
                    &std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                assert!(durable["receipt_id"].is_string());
                assert_eq!(durable["binding"]["transaction_id"], request["transaction_id"]);
                assert_eq!(durable["binding"]["generation"], request["generation"]);
                assert_eq!(std::fs::read(&cli).unwrap(), b"candidate cli");
                assert_eq!(std::fs::read(&backup).unwrap(), b"previous cli");
                assert!(!root.join(shutdown_flush::ROLLBACK_RECORD).exists());
                assert!(!root.join(shutdown_flush::HOLD_RECORD).exists());
                let _ = guard.shutdown_until(Instant::now() + Duration::from_secs(1));
                assert!(completed, "successful socket receipt left the stopped participant alive");
                assert_eq!(code, if mode == "SupervisedExit" { 42 } else { 0 },
                    "completion must respect the frozen restart owner, not reuse failed-flush exit 75");
                assert_eq!(exit_calls.load(Ordering::SeqCst), 1);
            }

            #[cfg_attr(not(target_os = "linux"), ignore = "requires isolated Linux network namespace")]
            #[tokio::test]
            async fn socket_success_receipt_completes_while_shutdown_tail_is_parked() {
                socket_success_completion("SupervisedExit", false, true).await;
            }

            #[cfg_attr(not(target_os = "linux"), ignore = "requires isolated Linux network namespace")]
            #[tokio::test]
            async fn socket_success_receipt_completes_after_requester_disappears() {
                socket_success_completion("SupervisedExit", true, false).await;
            }

            #[cfg_attr(not(target_os = "linux"), ignore = "requires isolated Linux network namespace")]
            #[tokio::test]
            async fn socket_success_receipt_preserves_external_handoff_owner() {
                socket_success_completion("TransactionalHandoff", false, false).await;
            }

            #[tokio::test(start_paused = true)]
            async fn http_drain_timeout_keeps_exit_zero_and_marks_only_the_receipt_unfinished() {
                let server = tokio::spawn(std::future::pending::<std::io::Result<()>>());
                let task = server.abort_handle();
                let (result, drained) = crate::server::drain_http_server(server).await;
                assert!(task.is_finished(), "timed-out HTTP task must be aborted and joined");
                // Ordinary shutdown keeps the clean-stop exit-0 contract
                // (#261/#363): a drain that misses the bound is not a process
                // error. Only the flush receipt sees the unfinished flag.
                assert!(result.is_ok());
                assert!(!drained, "an aborted HTTP producer is not a finished producer");
                assert!(crate::server::combine_server_shutdown_results(result, Ok(())).is_ok());
                let (clean, drained) =
                    crate::server::drain_http_server(tokio::spawn(async { Ok(()) })).await;
                assert!(clean.is_ok());
                assert!(drained);
            }

            #[tokio::test(start_paused = true)]
            async fn shutdown_flush_requires_the_real_server_producer_drain_to_finish() {
                use futures::FutureExt;
                for blocked in [true, false] {
                    let (dir, _, _, _) = fixture();
                    let agent = Arc::new(crate::Agent::builder()
                        .with_identity_dir(dir.path())
                        .with_user_key_path(dir.path().join("user.key"))
                        .with_machine_key(dir.path().join("machine.key"))
                        .with_agent_key_path(dir.path().join("agent.key"))
                        .with_agent_cert_path(dir.path().join("agent.cert"))
                        .with_contact_store_path(dir.path().join("contacts.json"))
                        .with_peer_cache_disabled().build().await.unwrap());
                    assert!(agent.network().is_none());
                    let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                        dir.path(), Arc::clone(&agent)).await.unwrap();
                    state.exec_service.shutdown().await;
                    let (release, released) = tokio::sync::oneshot::channel::<()>();
                    let producer = tokio::spawn(async move { let _ = released.await; })
                        .map(|result| result.map_err(|error| error.to_string())).shared();
                    let tracked = producer.clone();
                    assert!(state.spawn_shielded(async move { tracked.await.unwrap(); }));
                    let task = state.shielded_tasks.lock().unwrap().as_ref().unwrap()
                        .last().unwrap().abort_handle();
                    let mut release = Some(release);
                    if !blocked { release.take().unwrap().send(()).unwrap(); }
                    let start = tokio::time::Instant::now();
                    let complete = crate::server::drain_server_tasks(&state, Vec::new()).await;
                    if let Some(release) = release { release.send(()).unwrap(); }
                    // Join the owned work and observe the exact registered task end.
                    producer.await.unwrap();
                    while !task.is_finished() { tokio::task::yield_now().await; }
                    agent.try_shutdown().await.unwrap();
                    assert_eq!(complete, !blocked);
                    if blocked { assert!(start.elapsed() >= Duration::from_secs(10)); }
                }
            }

            #[tokio::test(start_paused = true)]
            async fn shutdown_flush_counts_an_aborted_grace_straggler_as_unfinished() {
                let (dir, _, _, _) = fixture();
                let agent = Arc::new(crate::Agent::builder()
                    .with_identity_dir(dir.path())
                    .with_user_key_path(dir.path().join("user.key"))
                    .with_machine_key(dir.path().join("machine.key"))
                    .with_agent_key_path(dir.path().join("agent.key"))
                    .with_agent_cert_path(dir.path().join("agent.cert"))
                    .with_contact_store_path(dir.path().join("contacts.json"))
                    .with_peer_cache_disabled().build().await.unwrap());
                assert!(agent.network().is_none());
                let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                    dir.path(), Arc::clone(&agent)).await.unwrap();
                state.exec_service.shutdown().await;
                let straggler = tokio::spawn(std::future::pending::<()>());
                let abort = straggler.abort_handle();
                let complete = crate::server::drain_server_tasks(&state, vec![straggler]).await;
                assert!(abort.is_finished(), "the straggler must be aborted and joined");
                // ADR 0094 §4: an abort does not stop blocking work the task
                // already started, so a task that missed the grace window is
                // not a finished producer whatever its cancelled JoinError says.
                assert!(!complete, "an aborted grace straggler must not count as finished");
                agent.try_shutdown().await.unwrap();
            }
        }
    };
}
