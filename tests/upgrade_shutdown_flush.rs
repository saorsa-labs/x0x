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
                    // Distinct from EX_TEMPFAIL (75) so the tests prove which
                    // exit path fired: success exits the plan's code, a failed
                    // started flush exits flush_failure_exit_code().
                    supervised_exit_code: Some(7),
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
                    Arc::new(move |_, _| {
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
                        assert_eq!(code, 7);
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
            fn supervised_exit_refusal_before_the_stop_keeps_the_daemon_running() {
                let (_dir, plan) = fixture();
                let original = std::fs::read(&plan.executable).unwrap();
                // The hook fails before the daemon stops behind it. Engineer
                // rulings 23/24 Oct 2026: an ordinary refusal — no exit, no
                // restore without a swap manifest, no hold — and the refusal
                // releases admission so a later supervised apply can run.
                let owner = flush::register(
                    plan.data_root.clone(),
                    Arc::new(|_, _| Err(io::Error::other("injected pre-stop refusal"))),
                )
                .unwrap();
                let mut exit_code = None;
                let result = AutoApplyUpgrader::new("x0xd").trigger_restart_with_exit(
                    &plan,
                    "2.0.0",
                    |code| exit_code = Some(code),
                );
                owner.join_workers();
                assert!(result.is_err());
                assert_eq!(exit_code, None, "a pre-stop refusal must not exit");
                assert_eq!(std::fs::read(&plan.executable).unwrap(), original);
                assert!(!plan.data_root.join(flush::ROLLBACK_RECORD).exists());
                assert!(!plan.data_root.join(flush::HOLD_RECORD).exists());
                // Engineer ruling 24 Oct 2026: the refused attempt's
                // receipt-less intent is cleared, so a later supervised
                // apply is admitted again instead of waiting for a restart.
                assert!(!plan.data_root.join(flush::RECORD).exists());
                flush::ensure_ready(&plan.data_root).unwrap();
                flush::reserve(&plan.data_root).unwrap();
            }

            #[test]
            fn supervised_exit_refusal_restores_the_swapped_pair_and_releases_admission() {
                // Engineer ruling 24 Oct 2026: a flush refused before the
                // daemon stops is not a failed start. The daemon keeps
                // serving, so the binaries this transaction swapped must go
                // back (verified fresh backups only) and admission must
                // re-open for a later supervised apply.
                let (_dir, plan) = fixture();
                let cli = plan.data_root.join("x0x");
                let daemon_backup = plan.executable.with_extension("backup");
                let cli_backup = plan.data_root.join("x0x.backup");
                std::fs::write(&plan.executable, b"swapped daemon").unwrap();
                std::fs::write(&daemon_backup, b"previous daemon").unwrap();
                std::fs::write(&cli, b"swapped cli").unwrap();
                std::fs::write(&cli_backup, b"previous cli").unwrap();
                let owner = flush::register(
                    plan.data_root.clone(),
                    Arc::new(|_, _| Err(io::Error::other("injected pre-stop refusal"))),
                )
                .unwrap();
                let mut exit_code = None;
                let result = AutoApplyUpgrader::new("x0xd")
                    .with_swapped_artifacts(vec![
                        (plan.executable.clone(), daemon_backup.clone()),
                        (cli.clone(), cli_backup.clone()),
                    ])
                    .trigger_restart_with_exit(&plan, "2.0.0", |code| exit_code = Some(code));
                owner.join_workers();
                assert!(result.is_err());
                assert_eq!(exit_code, None, "a refusal keeps the daemon serving");
                // Both halves of the pair are restored; the fresh backups
                // are consumed by the restore.
                assert_eq!(std::fs::read(&plan.executable).unwrap(), b"previous daemon");
                assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                assert!(!daemon_backup.exists());
                assert!(!cli_backup.exists());
                // No failed-release hold and no rollback record: the release
                // may be retried on the next normal update cycle.
                assert!(!plan.data_root.join(flush::HOLD_RECORD).exists());
                assert!(!plan.data_root.join(flush::ROLLBACK_RECORD).exists());
                // Admission re-opens: a second apply is accepted and an
                // ordinary shutdown is not parked by the refusal.
                flush::ensure_ready(&plan.data_root).unwrap();
                flush::reserve(&plan.data_root).unwrap();
                assert!(
                    !owner.seal_admission(),
                    "an ordinary shutdown after a refusal must not wait"
                );
            }

            #[test]
            fn supervised_exit_receipt_write_failure_after_the_stop_exits_tempfail() {
                let (_dir, plan) = fixture();
                let path = plan.data_root.join(flush::RECORD);
                let owner = flush::register(
                    plan.data_root.clone(),
                    Arc::new(move |_, stopped| {
                        stopped.store(true, Ordering::SeqCst);
                        // The intent is already durable; refuse only the
                        // receipt publication, after the daemon stopped.
                        std::fs::remove_file(&path)?;
                        std::fs::create_dir(&path)?;
                        Ok(())
                    }),
                )
                .unwrap();
                let mut exit_code = None;
                let result = AutoApplyUpgrader::new("x0xd").trigger_restart_with_exit(
                    &plan,
                    "2.0.0",
                    |code| exit_code = Some(code),
                );
                owner.join_workers();
                assert!(result.is_err());
                // Engineer ruling 23 Oct 2026: the started flush failed, so
                // the process exits EX_TEMPFAIL instead of staying up with
                // no API and no network, and the release is held.
                assert_eq!(exit_code, Some(restart::flush_failure_exit_code()));
                let hold: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(plan.data_root.join(flush::HOLD_RECORD)).unwrap(),
                )
                .unwrap();
                assert_eq!(hold["held_version"], serde_json::json!("2.0.0"));
                assert!(plan.data_root.join(flush::ROLLBACK_RECORD).is_file());
            }

            #[test]
            fn supervised_exit_after_failed_flush_without_a_swap_manifest_skips_the_restore() {
                // No swapped-artifact manifest means no fresh backup this
                // transaction owns. `<exe>.backup` may be a stale backup an
                // earlier upgrade left (engineer call, 23 Oct 2026), so the
                // recovery must not restore it; the hold and the EX_TEMPFAIL
                // exit still happen.
                let (_dir, plan) = fixture();
                let backup = plan.executable.with_extension("backup");
                std::fs::write(&plan.executable, b"swapped candidate").unwrap();
                std::fs::write(&backup, b"possibly stale backup").unwrap();
                let owner = flush::register(
                    plan.data_root.clone(),
                    Arc::new(|_, stopped| {
                        stopped.store(true, Ordering::SeqCst);
                        Err(io::Error::other("injected started flush failure"))
                    }),
                )
                .unwrap();
                let mut exit_code = None;
                let result = AutoApplyUpgrader::new("x0xd").trigger_restart_with_exit(
                    &plan,
                    "2.0.0",
                    |code| exit_code = Some(code),
                );
                owner.join_workers();
                assert!(result.is_err());
                assert_eq!(exit_code, Some(restart::flush_failure_exit_code()));
                // The unverified backup is never installed over the live bytes.
                assert_eq!(
                    std::fs::read(&plan.executable).unwrap(),
                    b"swapped candidate"
                );
                assert_eq!(std::fs::read(&backup).unwrap(), b"possibly stale backup");
                assert!(plan.data_root.join(flush::HOLD_RECORD).is_file());
                assert!(plan.data_root.join(flush::ROLLBACK_RECORD).is_file());
            }

            #[test]
            fn supervised_exit_after_failed_flush_restores_the_daemon_and_cli_pair() {
                // One flush per registration, so each half gets its own
                // fixture. The pairs the apply worker recorded stand in for
                // the swapped daemon and CLI, each with a fresh backup.
                for cli_backup_exists in [false, true] {
                    let (_dir, plan) = fixture();
                    let cli = plan.data_root.join("x0x");
                    let cli_backup = plan.data_root.join("x0x.backup");
                    let daemon_backup = plan.executable.with_extension("backup");
                    std::fs::write(&plan.executable, b"swapped daemon").unwrap();
                    std::fs::write(&daemon_backup, b"previous daemon").unwrap();
                    std::fs::write(&cli, b"swapped cli").unwrap();
                    if cli_backup_exists {
                        std::fs::write(&cli_backup, b"previous cli").unwrap();
                    }
                    let owner = flush::register(
                        plan.data_root.clone(),
                        Arc::new(|_, stopped| {
                            stopped.store(true, Ordering::SeqCst);
                            Err(io::Error::other("injected started flush failure"))
                        }),
                    )
                    .unwrap();
                    let set = vec![
                        (plan.executable.clone(), daemon_backup.clone()),
                        (cli.clone(), cli_backup.clone()),
                    ];
                    let mut exit_code = None;
                    let result = AutoApplyUpgrader::new("x0xd")
                        .with_swapped_artifacts(set)
                        .trigger_restart_with_exit(&plan, "2.0.0", |code| exit_code = Some(code));
                    owner.join_workers();
                    assert!(result.is_err());
                    assert_eq!(exit_code, Some(restart::flush_failure_exit_code()));
                    assert!(plan.data_root.join(flush::HOLD_RECORD).is_file());
                    if cli_backup_exists {
                        // Both backups present: restore both, never a mixed pair.
                        assert_eq!(std::fs::read(&plan.executable).unwrap(), b"previous daemon");
                        assert_eq!(std::fs::read(&cli).unwrap(), b"previous cli");
                        assert!(!daemon_backup.exists());
                        assert!(!cli_backup.exists());
                    } else {
                        // Missing CLI backup: restore neither half of the pair.
                        assert_eq!(std::fs::read(&plan.executable).unwrap(), b"swapped daemon");
                        assert_eq!(std::fs::read(&cli).unwrap(), b"swapped cli");
                    }
                }
            }

            #[test]
            fn failed_flush_then_restart_still_refuses_the_held_release() {
                // A deterministic flush failure applied twice must not retry
                // the same release: the first failed attempt writes the hold,
                // the restart's stale-record cleanup keeps it, and the next
                // apply of the same release is refused at the gate.
                let (_dir, plan) = fixture();
                let owner = flush::register(
                    plan.data_root.clone(),
                    Arc::new(|_, stopped| {
                        stopped.store(true, Ordering::SeqCst);
                        Err(io::Error::other("deterministic flush failure"))
                    }),
                )
                .unwrap();
                let mut exit_code = None;
                let result = AutoApplyUpgrader::new("x0xd").trigger_restart_with_exit(
                    &plan,
                    "2.0.0",
                    |code| exit_code = Some(code),
                );
                owner.join_workers();
                assert!(result.is_err());
                assert_eq!(exit_code, Some(restart::flush_failure_exit_code()));
                // The next startup runs exactly this cleanup.
                flush::clear_stale_records(&plan.data_root);
                assert!(plan.data_root.join(flush::HOLD_RECORD).is_file());
                assert_eq!(
                    flush::release_is_held(&plan.data_root, &semver::Version::new(2, 0, 0))
                        .unwrap()
                        .as_deref(),
                    Some("2.0.0"),
                    "the second application of the held release must be refused"
                );
                // A newer release is the automatic way past the hold.
                assert_eq!(
                    flush::release_is_held(&plan.data_root, &semver::Version::new(2, 0, 1))
                        .unwrap(),
                    None
                );
            }

            #[test]
            fn receipt_authorization_failure_after_the_stop_exits_tempfail() {
                // Engineer ruling 23 Oct 2026: any error after the flush
                // started ends in exit 75; a parked daemon with no API and
                // no network is forbidden. The receipt is real; only the
                // authorization binding mismatches.
                let (_dir, plan) = fixture();
                let owner = flush::register(
                    plan.data_root.clone(),
                    Arc::new(|_, stopped| {
                        stopped.store(true, Ordering::SeqCst);
                        Ok(())
                    }),
                )
                .unwrap();
                let binding =
                    flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                let receipt = flush::acknowledge(&plan.data_root, binding, || Ok(())).unwrap();
                owner.join_workers();
                let other =
                    flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                let mut exit_code = None;
                let result = authorize_receipt_after_stop(&receipt, &other, &mut |code| {
                    exit_code = Some(code)
                });
                assert!(result.is_err());
                assert_eq!(exit_code, Some(restart::flush_failure_exit_code()));
                // Nothing is restored and no hold is written: the flush
                // itself succeeded and the new bytes are durable.
                assert!(!plan.data_root.join(flush::HOLD_RECORD).exists());
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
                            Arc::new(move |_, _| {
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
                    let on_success = Box::new(move |_: &[(PathBuf, PathBuf)]| {
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
                    Arc::new(move |_, stopped| {
                        stopped.store(true, Ordering::SeqCst);
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
                let exited = Arc::new(std::sync::atomic::AtomicI32::new(-1));
                let exit_code = Arc::clone(&exited);
                let worker_plan = plan.clone();
                let (returned, result) = std::sync::mpsc::channel();
                let caller = std::thread::spawn(move || {
                    let outcome = AutoApplyUpgrader::new("x0xd").trigger_restart_with_exit(
                        &worker_plan,
                        "2.0.0",
                        |code| {
                            exit_code.store(code, Ordering::SeqCst);
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
                // An overrunning flush is a started failure: EX_TEMPFAIL,
                // never a late success receipt.
                assert_eq!(
                    exited.load(Ordering::SeqCst),
                    restart::flush_failure_exit_code()
                );
                assert!(record(&plan)["receipt_id"].is_null());
                assert!(plan.data_root.join("upgrade-flush-rollback.json").is_file());
            }
        }
    };
}
