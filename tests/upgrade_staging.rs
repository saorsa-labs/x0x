// Included and invoked inside server::routes::upgrade::tests by the lead.
// This standalone integration target deliberately has no tests: the expansion
// needs the existing private release/readback/apply seams. They replace external
// I/O and destructive execution; the real startup/apply preflight still runs.
// No Agent, real daemon, manager command, network or binary replacement runs.
#[allow(unused_macros)]
macro_rules! staging_regression_tests {
    () => {
        // A runnable yield keeps paused Tokio from jumping past a blocking
        // filesystem operation. Only acknowledged observations advance time.
        #[cfg(unix)]
        async fn staging_next_observation<F: std::future::Future>(
            mut startup: std::pin::Pin<&mut F>,
            observed: &mut tokio::sync::mpsc::UnboundedReceiver<crate::upgrade::staging::Decision>,
            deadline: std::time::Instant,
        ) -> std::result::Result<crate::upgrade::staging::Decision, F::Output> {
            loop {
                assert!(std::time::Instant::now() < deadline, "staging fixture wall-clock bound");
                tokio::select! {
                    biased;
                    result = startup.as_mut() => return Err(result),
                    decision = observed.recv() => {
                        return Ok(decision.expect("staging observer stays connected"));
                    }
                    _ = tokio::task::yield_now() => {}
                }
            }
        }

        #[cfg(unix)]
        #[tokio::test(start_paused = true)]
        async fn staging_startup_waits_before_applying_once_within_its_window() {
            staging_startup_case(false, false).await;
        }

        #[cfg(unix)]
        #[tokio::test(start_paused = true)]
        async fn staging_startup_shutdown_preserves_wait_without_applying() {
            staging_startup_case(true, false).await;
        }

        #[cfg(unix)]
        #[tokio::test(start_paused = true)]
        async fn staging_startup_shutdown_during_guide_download_preserves_bytes() {
            staging_startup_case(false, true).await;
        }

        #[cfg(unix)]
        async fn staging_startup_case(shutdown_while_waiting: bool, cancel_guide: bool) {
            use sha2::Digest;
            use std::future::Future;

            let wall_deadline = std::time::Instant::now() + Duration::from_secs(30);
            let fixture_root = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning")
                        .join("upgrade-staging-fixtures")
                });
            std::fs::create_dir_all(&fixture_root).expect("owned staging fixture root");
            let fixture = tempfile::Builder::new()
                .prefix("startup-window-")
                .tempdir_in(&fixture_root)
                .expect("owned staging data directory");
            let root = fixture.path().canonicalize().unwrap();
            let data_dir = root.join("data");
            let identity_dir = root.join("identity");
            std::fs::create_dir(&data_dir).unwrap();
            std::fs::create_dir(&identity_dir).unwrap();
            let (mut runtime, shutdown_tx) = e2e_startup_runtime(&data_dir);
            let _current_path = crate::upgrade::apply::current_binary_path_seam::install(
                data_dir.join("x0xd"),
            );
            runtime.staging.identity_root = identity_dir.clone();
            runtime.staging.machine_id = [42; 32];
            let (observed_tx, mut observed_rx) = tokio::sync::mpsc::unbounded_channel();
            runtime.staging.observed = Some(Arc::new(move |decision| {
                observed_tx.send(decision).unwrap();
            }));
            let started = tokio::time::Instant::now();
            runtime.staging.clock = Some(Arc::new(move || {
                Ok(crate::upgrade::probe::ProbeClock {
                    boot_id: "startup-fixture".to_owned(),
                    monotonic_ms: 1_000
                        + u64::try_from(started.elapsed().as_millis())
                            .map_err(std::io::Error::other)?,
                })
            }));
            let install = runtime.staging.install.clone();
            let original_install = std::fs::read(&install).unwrap();

            // Disable only systemd's independent start-rate wait. Any wait
            // observed below must come from the configured rollout window.
            // The loaded executable and argv[0] describe the owned install;
            // the PID and remaining arguments still describe this process.
            let mut scenario = one_call_scenario("0", "5");
            let current = crate::upgrade::apply::current_binary_path().unwrap();
            for call in &mut scenario.calls {
                call.show_output = call
                    .show_output
                    .replace(current.to_str().unwrap(), install.to_str().unwrap())
                    .replace(&restart::current_argv()[0], install.to_str().unwrap());
            }
            let _readback = restart::systemd_readback_seam::install(scenario);
            let mut manifest = manifest_for_this_platform("9.9.9");
            manifest.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("current release timestamp")
                .as_secs();
            let guide = data_dir.join("SKILL.md");
            let original_guide = b"owned original guide";
            let candidate_guide = b"owned verified replacement guide".to_vec();
            let (download_started_tx, mut download_started_rx) = tokio::sync::oneshot::channel();
            let (continue_download_tx, continue_download_rx) = tokio::sync::oneshot::channel();
            let _download = if cancel_guide {
                std::fs::write(&guide, original_guide).unwrap();
                manifest.skill_sha256 = sha2::Sha256::digest(&candidate_guide).into();
                manifest.skill_url = "inert-skill-fixture://owned-guide".into();
                Some(skill_download_seam::install(async move {
                    download_started_tx.send(()).unwrap();
                    continue_download_rx.await.unwrap();
                    candidate_guide
                }))
            } else {
                None
            };
            let window_minutes = if cancel_guide { 0 } else { 60 };
            let manifest_json = serde_json::to_vec(&manifest).unwrap();
            let request = crate::upgrade::staging::StagingRequest {
                install: install.clone(),
                data_root: data_dir.clone(),
                identity_root: identity_dir,
                machine_id: [42; 32],
                version: manifest.version.clone(),
                manifest_sha256: sha2::Sha256::digest(&manifest_json).into(),
                archive_sha256: manifest.assets[0].archive_sha256,
                window_minutes,
            };
            let attempts = Arc::new(AtomicU64::new(0));
            let hook_attempts = Arc::clone(&attempts);
            let hook_request = request.clone();
            let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(
                move |_plan, manifest| {
                    assert_eq!(
                        crate::upgrade::staging::read_receipt(&hook_request)
                            .unwrap()
                            .unwrap()
                            .remaining,
                        Duration::ZERO,
                        "the actual apply hook requires a durable due checkpoint"
                    );
                    hook_attempts.fetch_add(1, Ordering::SeqCst);
                    x0x::upgrade::UpgradeResult::Success {
                        version: manifest.version.clone(),
                    }
                },
            ));
            let _release =
                startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
                    manifest,
                    manifest_json,
                    signature: Vec::new(),
                    gossip_payload: Vec::new(),
                });
            let mut config = DaemonConfig {
                data_dir: data_dir.clone(),
                ..Default::default()
            };
            config.update.rollout_window_minutes = window_minutes;
            let apply_lock = Arc::clone(&runtime.upgrade_apply_lock);
            let startup = run_startup_update_check(&config, None, Some(runtime));
            tokio::pin!(startup);

            let first = staging_next_observation(startup.as_mut(), &mut observed_rx, wall_deadline)
                .await
                .unwrap_or_else(|result| panic!("startup completed before its wait: {result:?}"));
            if cancel_guide {
                assert_eq!(first, crate::upgrade::staging::Decision::Due);
                loop {
                    assert!(std::time::Instant::now() < wall_deadline);
                    tokio::select! {
                        biased;
                        result = startup.as_mut() => panic!("startup finished before download: {result:?}"),
                        started = &mut download_started_rx => { started.unwrap(); break; }
                        _ = tokio::task::yield_now() => {}
                    }
                }
                let receipt_path = crate::upgrade::staging::receipt_path(&request).unwrap();
                let retained = std::fs::read(&receipt_path).unwrap();
                shutdown_tx.send(true).unwrap();
                let result = staging_next_observation(
                    startup.as_mut(), &mut observed_rx, wall_deadline,
                ).await.expect_err("shutdown must drop the pending guide download");
                assert!(matches!(&result, Ok(None)), "shutdown result: {result:?}");
                assert!(continue_download_tx.send(()).is_err(), "download future must be dropped");
                assert_eq!(attempts.load(Ordering::SeqCst), 0);
                assert_eq!(std::fs::read(&guide).unwrap(), original_guide);
                assert_eq!(std::fs::read(install).unwrap(), original_install);
                assert_eq!(std::fs::read(receipt_path).unwrap(), retained);
                assert!(!std::fs::read_dir(&data_dir).unwrap().any(|entry| {
                    entry.unwrap().file_name().to_string_lossy().starts_with("SKILL.md.tmp.")
                }));
                assert!(apply_lock.try_lock().is_ok());
                return;
            }
            assert_eq!(
                first,
                crate::upgrade::staging::Decision::Waiting(Duration::from_secs(3260))
            );
            assert_eq!(started.elapsed(), Duration::ZERO);
            let checkpoint = crate::upgrade::staging::read_receipt(&request)
                .unwrap()
                .expect("startup must retain its first durable receipt while waiting");
            // Independent SHA256 integer reference for [42;32] + "9.9.9":
            // floor(16705966475516218572 * 3600 / 2^64) = 3260.
            assert_eq!(checkpoint.chosen_delay, Duration::from_secs(3260));
            assert_eq!(checkpoint.first_boot_id, "startup-fixture");
            assert_eq!(checkpoint.first_receipt_ms, 1_000);
            assert_eq!(checkpoint.manifest_sha256, request.manifest_sha256);
            assert_eq!(checkpoint.archive_sha256, request.archive_sha256);
            assert_eq!(checkpoint.data_root, data_dir);
            assert_eq!(checkpoint.identity_root, request.identity_root);

            tokio::time::advance(Duration::from_secs(1)).await;
            let early = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(startup.as_mut().poll(cx))
            }).await;
            assert!(early.is_pending(), "startup must retain the pending apply: {early:?}");
            assert_eq!(
                attempts.load(Ordering::SeqCst), 0,
                "a positive rollout window must prevent immediate destructive admission"
            );
            assert!(apply_lock.try_lock().is_ok(), "the wait must release the apply mutex");
            assert_eq!(started.elapsed(), Duration::from_secs(1));

            if shutdown_while_waiting {
                let receipt_path = crate::upgrade::staging::receipt_path(&request).unwrap();
                let retained = std::fs::read(&receipt_path).unwrap();
                shutdown_tx.send(true).unwrap();
                let result = staging_next_observation(
                    startup.as_mut(), &mut observed_rx, wall_deadline,
                ).await.expect_err("shutdown must finish the same pending startup operation");
                assert!(matches!(&result, Ok(None)), "shutdown result: {result:?}");
                assert_eq!(attempts.load(Ordering::SeqCst), 0);
                assert_eq!(std::fs::read(receipt_path).unwrap(), retained);
                assert_eq!(std::fs::read(install).unwrap(), original_install);
                assert_eq!(started.elapsed(), Duration::from_secs(1));
                assert!(apply_lock.try_lock().is_ok());
                return;
            }

            let mut next = first;
            let mut elapsed_in_wait = Duration::from_secs(1);
            let result = loop {
                if let crate::upgrade::staging::Decision::Waiting(wait) = next {
                    let step = wait.min(Duration::from_secs(30)).saturating_sub(elapsed_in_wait);
                    assert!(started.elapsed() + step <= Duration::from_secs(60 * 60));
                    tokio::time::advance(step).await;
                }
                match staging_next_observation(
                    startup.as_mut(), &mut observed_rx, wall_deadline,
                ).await {
                    Ok(decision) => {
                        next = decision;
                        elapsed_in_wait = Duration::ZERO;
                    }
                    Err(result) => break result,
                }
            };
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                1,
                "the retained startup operation must eventually apply exactly once"
            );
            assert!(
                matches!(&result, Ok(Some(version)) if version == "9.9.9"),
                "the due release must apply successfully: {result:?}"
            );
            assert!(started.elapsed() >= Duration::from_secs(3260));
            assert!(started.elapsed() <= Duration::from_secs(60 * 60));
            assert_eq!(std::fs::read(install).unwrap(), original_install);
        }
    };
}

// Runtime cancellation and pair-state admission controls; pure receipt tests
// live in upgrade_staging_core.rs and run inside the private receipt module.
#[allow(unused_macros)]
macro_rules! staging_runtime_regression_tests {
    () => {
        #[cfg(unix)]
        mod staging_runtime_regressions {
            use crate::upgrade::{probe::ProbeClock, staging::*};
            use std::{fs, time::Duration};

            fn fixture() -> (tempfile::TempDir, StagingRequest, fs::File) {
                let root = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| {
                        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join(".planning/upgrade-staging-fixtures")
                    });
                fs::create_dir_all(&root).unwrap();
                let dir = tempfile::Builder::new()
                    .prefix("receipt-")
                    .tempdir_in(root)
                    .unwrap();
                let root = fs::canonicalize(dir.path()).unwrap();
                fs::write(root.join("x0xd"), b"owned installed fixture").unwrap();
                fs::create_dir(root.join("data")).unwrap();
                fs::create_dir(root.join("identity")).unwrap();
                let request = StagingRequest {
                    install: root.join("x0xd"),
                    data_root: root.join("data"),
                    identity_root: root.join("identity"),
                    machine_id: [42; 32],
                    version: "1.2.3".into(),
                    manifest_sha256: [3; 32],
                    archive_sha256: [4; 32],
                    window_minutes: 60,
                };
                let lock = crate::upgrade::acquire_host_upgrade_lock(&request.install).unwrap();
                (dir, request, lock)
            }

            fn clock(boot: &str, milliseconds: u64) -> ProbeClock {
                ProbeClock {
                    boot_id: boot.into(),
                    monotonic_ms: milliseconds,
                }
            }

            // Polling wait_for_staging once starts its blocking lock acquisition.
            // Retaining the actual lock prevents either record creation or progress.
            // A Weak clock owner is a completion witness for every cloned worker:
            // checking bytes immediately after cancellation would miss a late write.
            async fn cancelled_receipt_worker(closed_watch: bool, existing: bool) {
                use std::future::Future;
                use std::sync::Arc;
                let (dir, request, lock) = fixture();
                let _current_path = crate::upgrade::apply::current_binary_path_seam::install(
                    dir.path().canonicalize().unwrap().join("x0xd"),
                );
                if existing {
                    observe(&request, &clock("a", 1000)).unwrap();
                }
                let path = receipt_path(&request).unwrap();
                let before = fs::read(&path).ok();
                let test_clock: crate::upgrade::staging_runtime::Clock =
                    Arc::new(|| Ok(clock("a", 10_000)));
                let owners = Arc::downgrade(&test_clock);
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                {
                    let upgrader = crate::upgrade::apply::AutoApplyUpgrader::new("x0xd")
                        .with_staging_request(request.clone())
                        .with_staging_clock(Some(test_clock));
                    let (sender, mut shutdown) = tokio::sync::watch::channel(false);
                    let mut sender = Some(sender);
                    if closed_watch {
                        drop(sender.take());
                    }
                    let wait = upgrader.wait_for_staging(&mut shutdown);
                    tokio::pin!(wait);
                    if !closed_watch {
                        let first = std::future::poll_fn(|cx| {
                            std::task::Poll::Ready(wait.as_mut().poll(cx))
                        })
                        .await;
                        assert!(
                            first.is_pending(),
                            "actual install lock must block the worker"
                        );
                        assert!(
                            owners.strong_count() >= 2,
                            "worker must carry the real gate"
                        );
                        sender.as_ref().unwrap().send(true).unwrap();
                    }
                    let result = loop {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "cancelled worker deadline"
                        );
                        tokio::select! {
                            biased;
                            result = wait.as_mut() => break result,
                            _ = tokio::task::yield_now() => {}
                        }
                    };
                    assert!(result.is_err(), "shutdown must refuse staging");
                    assert_eq!(fs::read(&path).ok(), before);
                }
                drop(lock);
                while owners.strong_count() != 0 {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "queued worker must finish"
                    );
                    tokio::task::yield_now().await;
                }
                assert_eq!(
                    fs::read(&path).ok(),
                    before,
                    "cancelled worker must not write later"
                );
                assert_eq!(
                    fs::read(&request.install).unwrap(),
                    b"owned installed fixture"
                );
            }

            #[tokio::test]
            async fn staging_cancelled_worker_cannot_write_after_the_owned_lock_is_released() {
                for existing in [false, true] {
                    cancelled_receipt_worker(false, existing).await;
                }
            }

            #[tokio::test]
            async fn staging_closed_false_watch_cannot_create_or_advance_a_receipt() {
                for existing in [false, true] {
                    cancelled_receipt_worker(true, existing).await;
                }
            }

            #[test]
            fn staging_markerless_pair_main_refuses_unknown_or_unresolved_records() {
                use crate::upgrade::{pair::*, staging_runtime::Gate};
                use sha2::{Digest, Sha256};
                let (_dir, mut request, _lock) = fixture();
                request.window_minutes = 0;
                let root = request.install.parent().unwrap();
                let previous = fs::read(&request.install).unwrap();
                let candidate = b"owned candidate bytes";
                let transaction = "11111111-1111-4111-8111-111111111111";
                let input = BinaryInput {
                    target: request.install.clone(),
                    staged: root.join("candidate-input"),
                    previous_version: "1.0.0".into(),
                    previous_sha256: Sha256::digest(&previous).into(),
                    candidate_sha256: Sha256::digest(candidate).into(),
                };
                let backup = root.join(format!("x0xd.backup-1.0.0-{transaction}"));
                let prepared = root.join(format!("x0xd.candidate-1.2.3-{transaction}"));
                fs::write(&input.staged, candidate).unwrap();
                fs::write(&backup, &previous).unwrap();
                fs::write(&prepared, candidate).unwrap();
                let plan = PairPlan {
                    request: PairRequest {
                        install: request.install.clone(),
                        candidate_version: request.version.clone(),
                        manifest_sha256: request.manifest_sha256,
                        archive_sha256: request.archive_sha256,
                        daemon: input.clone(),
                        cli: CliInput::Split {
                            path: None,
                            reason: "independently installed CLI outside this fixture".into(),
                        },
                        skill: None,
                        probe: ProbeBinding {
                            transaction_id: "22222222-2222-4222-8222-222222222222".into(),
                            platform: crate::upgrade::manifest::current_platform_target()
                                .unwrap()
                                .into(),
                            daemon_sha256: input.candidate_sha256,
                            cli_sha256: [5; 32],
                        },
                    },
                    daemon: PreparedBinary {
                        input,
                        backup: backup.clone(),
                        candidate: prepared.clone(),
                        restore: root.join(format!("x0xd.restore-{transaction}")),
                        previous_mode: 0o644,
                    },
                    cli: None,
                    staged_skill: None,
                    previous_record: None,
                };
                // This is persisted-input parser coverage, not proof that a
                // transaction ran. Real target/backup bytes and the independently
                // serialized immutable-plan hash give the decoder a valid control.
                let restored = PairRecord {
                    schema_version: 1,
                    record_kind: "pair".into(),
                    transaction_id: transaction.into(),
                    sequence: 7,
                    phase: PairPhase::Restored,
                    plan_sha256: Sha256::digest(serde_json::to_vec(&plan).unwrap()).into(),
                    plan,
                    daemon_progress: PairProgress {
                        swap_started: true,
                        swapped: true,
                        restore_started: true,
                        restored: true,
                    },
                    cli_progress: None,
                    cause: Some("owned fixture swap failure".into()),
                };
                let valid = serde_json::to_vec(&restored).unwrap();
                let path = pair_record_path(&request.install).unwrap();
                let pending = pair_pending_path(&request.install).unwrap();
                assert!(!pending.exists());
                let mut refused = vec![b"{torn".to_vec()];
                for field in ["schema_version", "record_kind", "extra"] {
                    let mut value = serde_json::to_value(&restored).unwrap();
                    value[field] = match field {
                        "schema_version" => serde_json::json!(99),
                        "record_kind" => serde_json::json!("future_pair"),
                        _ => serde_json::json!(true),
                    };
                    refused.push(serde_json::to_vec(&value).unwrap());
                }
                for phase in [
                    PairPhase::Prepared,
                    PairPhase::Swapping,
                    PairPhase::Swapped,
                    PairPhase::RollingBack,
                    PairPhase::Restoring,
                    PairPhase::RecoveryFailed,
                ] {
                    let mut unresolved = restored.clone();
                    unresolved.phase = phase;
                    let bytes = serde_json::to_vec(&unresolved).unwrap();
                    fs::write(&path, &bytes).unwrap();
                    assert_eq!(
                        read_pair_record(&request.install).unwrap().unwrap().phase,
                        phase
                    );
                    refused.push(bytes);
                }
                let gate = Gate {
                    request: request.clone(),
                    clock: Some(std::sync::Arc::new(|| Ok(clock("a", 1000)))),
                    observed: None,
                };
                for bytes in refused {
                    fs::write(&path, &bytes).unwrap();
                    assert!(gate.require_due(&request.install).is_err());
                    assert_eq!(fs::read(&path).unwrap(), bytes);
                    assert!(
                        !receipt_path(&request).unwrap().exists(),
                        "refusal cannot create a receipt"
                    );
                    assert!(!pending.exists());
                }
                fs::write(&path, &valid).unwrap();
                assert_eq!(
                    read_pair_record(&request.install).unwrap().unwrap().phase,
                    PairPhase::Restored
                );
                gate.require_due(&request.install).unwrap();
                assert_eq!(
                    read_receipt(&request).unwrap().unwrap().remaining,
                    Duration::ZERO
                );
                assert_eq!(fs::read(&path).unwrap(), valid);
                fs::write(&pending, b"{torn intent").unwrap();
                let receipt = fs::read(receipt_path(&request).unwrap()).unwrap();
                assert!(gate.require_due(&request.install).is_err());
                assert_eq!(fs::read(&pending).unwrap(), b"{torn intent");
                assert_eq!(fs::read(receipt_path(&request).unwrap()).unwrap(), receipt);
                assert_eq!(fs::read(&path).unwrap(), valid);
                assert_eq!(fs::read(&request.install).unwrap(), previous);
                assert_eq!(fs::read(backup).unwrap(), previous);
                assert_eq!(fs::read(prepared).unwrap(), candidate);
            }
        }
    };
}
