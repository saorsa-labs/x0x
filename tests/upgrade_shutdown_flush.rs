// Expanded in upgrade::apply. Owned files and injected shutdown sinks only;
// no daemon, supervisor, service, socket or actual process exit is started.
#[allow(unused_macros)]
macro_rules! shutdown_flush_regression_tests {
    () => {
        #[cfg(unix)]
        mod shutdown_flush_regressions {
            use super::*;
            use crate::upgrade::shutdown_flush as flush;
            use std::{
                io,
                sync::{
                    atomic::{AtomicBool, Ordering},
                    Arc,
                },
                time::Duration,
            };

            fn fixture() -> (tempfile::TempDir, restart::RestartPlan) {
                let root = std::env::var_os("X0X_UPGRADE_FLUSH_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join("target/upgrade-flush-fixtures")
                    });
                std::fs::create_dir_all(&root).unwrap();
                let dir = tempfile::Builder::new()
                    .prefix("supervised-")
                    .tempdir_in(root)
                    .unwrap();
                let root = dir.path().canonicalize().unwrap();
                let executable = root.join("x0xd");
                std::fs::write(&executable, b"owned candidate fixture").unwrap();
                let plan = restart::RestartPlan {
                    mode: restart::RestartMode::SupervisedExit,
                    supervised_exit_code: Some(75),
                    supervision_signal: Some("fixture-manager".into()),
                    executable: executable.clone(),
                    argv: vec![executable.to_str().unwrap().into()],
                    cwd: root.clone(),
                    data_root: root,
                    api_addr: "127.0.0.1:1".parse().unwrap(),
                    launchd_verified: None,
                    systemd_verified: None,
                };
                (dir, plan)
            }
            fn record(plan: &restart::RestartPlan) -> serde_json::Value {
                serde_json::from_slice(&std::fs::read(plan.data_root.join(flush::RECORD)).unwrap())
                    .unwrap()
            }

            #[test]
            fn supervised_exit_accepts_only_the_completed_transaction_receipt() {
                let (_dir, plan) = fixture();
                let observed = plan.clone();
                let flushed = Arc::new(AtomicBool::new(false));
                let completed = Arc::clone(&flushed);
                let owner = flush::register(
                    plan.data_root.clone(),
                    Arc::new(move |_| {
                        assert!(observed.handoff_path().is_file());
                        assert!(record(&observed)["receipt_id"].is_null());
                        completed.store(true, Ordering::SeqCst);
                        Ok(())
                    }),
                )
                .unwrap();
                let mut exited = false;
                AutoApplyUpgrader::new("x0xd")
                    .trigger_restart_with_exit(&plan, "2.0.0", |code| {
                        assert_eq!(code, 75);
                        assert!(flushed.load(Ordering::SeqCst));
                        let saved = record(&plan);
                        assert!(saved["receipt_id"].as_str().is_some());
                        let handoff = restart::UpgradeHandoff::read(&plan.handoff_path()).unwrap();
                        let binding = flush::Binding::new(
                            saved["binding"]["transaction_id"].as_str().unwrap().into(),
                            saved["binding"]["generation"].as_u64().unwrap(),
                            &handoff,
                        )
                        .unwrap();
                        assert_eq!(saved["binding"], serde_json::to_value(binding).unwrap());
                        exited = true;
                    })
                    .unwrap();
                owner.join_workers();
                assert!(exited);
            }

            #[test]
            fn supervised_exit_refuses_failed_flush_or_failed_receipt_write() {
                for receipt_write_failure in [false, true] {
                    let (_dir, plan) = fixture();
                    let path = plan.data_root.join(flush::RECORD);
                    let owner = flush::register(
                        plan.data_root.clone(),
                        Arc::new(move |_| {
                            if receipt_write_failure {
                                std::fs::remove_file(&path)?;
                                std::fs::create_dir(&path)?;
                                Ok(())
                            } else {
                                Err(io::Error::other("injected component flush failure"))
                            }
                        }),
                    )
                    .unwrap();
                    let mut exited = false;
                    assert!(AutoApplyUpgrader::new("x0xd")
                        .trigger_restart_with_exit(&plan, "2.0.0", |_| exited = true)
                        .is_err());
                    owner.join_workers();
                    assert!(!exited);
                    if !receipt_write_failure {
                        assert!(record(&plan)["receipt_id"].is_null());
                    }
                }
            }

            #[test]
            fn supervised_exit_refuses_without_a_shutdown_owner_or_receipt() {
                let (_dir, plan) = fixture();
                let mut exited = false;
                assert!(AutoApplyUpgrader::new("x0xd")
                    .trigger_restart_with_exit(&plan, "2.0.0", |_| exited = true)
                    .is_err());
                assert!(!exited);
                assert!(!plan.data_root.join(flush::RECORD).exists());
            }

            #[tokio::test(flavor = "current_thread")]
            async fn supervised_replacement_reserves_shutdown_before_changing_bytes() {
                for normal_shutdown_wins in [true, false] {
                    let (_dir, plan) = fixture();
                    let original = std::fs::read(&plan.executable).unwrap();
                    let scratch = plan.data_root.join("scratch");
                    std::fs::create_dir(&scratch).unwrap();
                    let incoming = scratch.join("candidate");
                    std::fs::write(&incoming, b"new candidate").unwrap();
                    let flushed = Arc::new(AtomicBool::new(false));
                    let observed = Arc::clone(&flushed);
                    let owner = Arc::new(
                        flush::register(
                            plan.data_root.clone(),
                            Arc::new(move |_| {
                                observed.store(true, Ordering::SeqCst);
                                Ok(())
                            }),
                        )
                        .unwrap(),
                    );
                    let reservation = flush::reserve(&plan.data_root).unwrap();
                    if normal_shutdown_wins {
                        assert!(!owner.seal_admission());
                    }
                    let retained = Arc::clone(&owner);
                    let exit = Arc::new(AtomicBool::new(false));
                    let exited = Arc::clone(&exit);
                    let restarted_plan = plan.clone();
                    let for_restart = reservation.clone();
                    let on_success = Box::new(move || {
                        assert!(
                            retained.seal_admission(),
                            "normal shutdown must retain the admitted replacement owner"
                        );
                        assert_eq!(
                            std::fs::read(&restarted_plan.executable).unwrap(),
                            b"new candidate"
                        );
                        assert!(!restarted_plan.data_root.join(flush::RECORD).exists());
                        AutoApplyUpgrader::new("x0xd")
                            .with_flush_reservation(Some(for_restart))
                            .trigger_restart_with_exit(&restarted_plan, "2.0.0", |_| {
                                exited.store(true, Ordering::SeqCst);
                            })
                            .unwrap();
                    });
                    let result = apply_replacements_with_permit(
                        Upgrader::new(plan.executable.clone(), semver::Version::new(1, 0, 0)),
                        incoming,
                        semver::Version::new(2, 0, 0),
                        None,
                        TempDirGuard { path: scratch },
                        Some(on_success),
                        None,
                        None,
                        Some(reservation),
                    )
                    .await;
                    owner.join_workers();
                    assert_eq!(result.is_err(), normal_shutdown_wins);
                    assert_eq!(exit.load(Ordering::SeqCst), !normal_shutdown_wins);
                    assert_eq!(flushed.load(Ordering::SeqCst), !normal_shutdown_wins);
                    if normal_shutdown_wins {
                        assert_eq!(std::fs::read(&plan.executable).unwrap(), original);
                        assert!(!plan.executable.with_extension("backup").exists());
                        assert!(!plan.data_root.join(flush::RECORD).exists());
                    } else {
                        assert!(record(&plan)["receipt_id"].is_string());
                    }
                }
            }

            #[test]
            fn supervised_exit_timeout_never_authorizes_a_late_success() {
                let (_dir, plan) = fixture();
                let (entered, entered_rx) = std::sync::mpsc::channel();
                let (release, released) = std::sync::mpsc::channel();
                let released = std::sync::Mutex::new(released);
                let owner = flush::register_with_limit(
                    plan.data_root.clone(),
                    Arc::new(move |_| {
                        let _ = entered.send(());
                        released
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .map_err(io::Error::other)
                    }),
                    Duration::from_millis(500),
                )
                .unwrap();
                let exited = Arc::new(AtomicBool::new(false));
                let exit_called = Arc::clone(&exited);
                let worker_plan = plan.clone();
                let (returned, result) = std::sync::mpsc::channel();
                let caller = std::thread::spawn(move || {
                    let outcome = AutoApplyUpgrader::new("x0xd").trigger_restart_with_exit(
                        &worker_plan,
                        "2.0.0",
                        |_| {
                            exit_called.store(true, Ordering::SeqCst);
                        },
                    );
                    let _ = returned.send(outcome);
                });
                let did_enter = entered_rx.recv_timeout(Duration::from_secs(5));
                let outcome = result.recv_timeout(Duration::from_secs(3));
                let _ = release.send(());
                caller.join().unwrap();
                owner.join_workers();
                did_enter.unwrap();
                assert!(outcome.unwrap().is_err());
                assert!(!exited.load(Ordering::SeqCst));
                assert!(record(&plan)["receipt_id"].is_null());
                assert!(plan.data_root.join("upgrade-flush-rollback.json").is_file());
            }
        }
    };
}
