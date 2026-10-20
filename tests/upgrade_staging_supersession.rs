// Expanded inside server::routes::upgrade::tests alongside the existing staging
// macro. The standalone integration target is inert. This RED uses two real
// startup operations; no selection adapter, Agent, network or binary swap runs.
#[allow(unused_macros)]
macro_rules! staging_supersession_regression_tests {
    () => {
        #[cfg(unix)]
        #[tokio::test(start_paused = true)]
        async fn staging_newer_durable_receipt_refuses_the_older_owned_startup() {
            use sha2::Digest;

            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let evidence = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(".planning/upgrade-staging-fixtures"));
            std::fs::create_dir_all(&evidence).unwrap();
            let dir = tempfile::Builder::new().prefix("supersession-").tempdir_in(evidence).unwrap();
            let root = dir.path().canonicalize().unwrap();
            // Create the owned install once. Both operations use the same real
            // participant, restart context, shutdown watch and apply mutex.
            let (mut older_runtime, _shutdown) = e2e_startup_runtime(&root);
            let _current_path = crate::upgrade::apply::current_binary_path_seam::install(
                root.join("x0xd"),
            );
            let started = tokio::time::Instant::now();
            older_runtime.staging.machine_id = [42; 32];
            older_runtime.staging.clock = Some(Arc::new(move || {
                Ok(crate::upgrade::probe::ProbeClock {
                    boot_id: "supersession-fixture".into(),
                    monotonic_ms: 1000 + u64::try_from(started.elapsed().as_millis())
                        .map_err(std::io::Error::other)?,
                })
            }));
            let mut newer_runtime = StartupUpdateCheckRuntime {
                restart_context: older_runtime.restart_context.clone(),
                upgrade_apply_lock: Arc::clone(&older_runtime.upgrade_apply_lock),
                shutdown_watch: older_runtime.shutdown_watch.clone(),
                staging: older_runtime.staging.clone(),
            };
            let (older_tx, mut older_rx) = tokio::sync::mpsc::unbounded_channel();
            older_runtime.staging.observed = Some(Arc::new(move |decision| {
                older_tx.send(decision).unwrap();
            }));
            let (newer_tx, mut newer_rx) = tokio::sync::mpsc::unbounded_channel();
            newer_runtime.staging.observed = Some(Arc::new(move |decision| {
                newer_tx.send(decision).unwrap();
            }));
            let install = older_runtime.staging.install.clone();
            let original = std::fs::read(&install).unwrap();
            let apply_lock = Arc::clone(&older_runtime.upgrade_apply_lock);
            let _readback = restart::systemd_readback_seam::install(staging_readback(
                one_call_scenario("0", "5"), &older_runtime,
            ));
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let release = |version: &str| {
                let mut manifest = manifest_for_this_platform(version);
                manifest.timestamp = timestamp;
                let manifest_json = serde_json::to_vec(&manifest).unwrap();
                crate::upgrade::monitor::VerifiedRelease {
                    manifest, manifest_json, signature: Vec::new(), gossip_payload: Vec::new(),
                }
            };
            let older_release = release("9.9.9");
            let newer_release = release("9.9.10");
            let request = |release: &crate::upgrade::monitor::VerifiedRelease| {
                crate::upgrade::staging::StagingRequest {
                    install: install.clone(), data_root: root.clone(),
                    identity_root: root.clone(), machine_id: [42; 32],
                    version: release.manifest.version.clone(),
                    manifest_sha256: sha2::Sha256::digest(&release.manifest_json).into(),
                    archive_sha256: release.manifest.assets[0].archive_sha256,
                    window_minutes: 60,
                }
            };
            let older_request = request(&older_release);
            let newer_request = request(&newer_release);
            let attempts = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
            let counted = Arc::clone(&attempts);
            let expected_install = install.clone();
            let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |plan, manifest| {
                assert_eq!(plan.executable, expected_install);
                counted.lock().unwrap().push(manifest.version.clone());
                // Observe admission only. This does not change installed bytes,
                // the compiled VERSION, or any reported running version.
                x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
            }));
            let mut config = DaemonConfig { data_dir: root, ..Default::default() };
            config.update.rollout_window_minutes = 60;

            let older_injection = startup_release_seam::install(older_release);
            let older = run_startup_update_check(&config, None, Some(older_runtime));
            tokio::pin!(older);
            assert_eq!(staging_next_observation(older.as_mut(), &mut older_rx, deadline).await.unwrap(),
                crate::upgrade::staging::Decision::Waiting(Duration::from_secs(3260)));
            // The first real operation has consumed its release. Its injection
            // guard must not later clear the second operation's input.
            drop(older_injection);
            let older_first = crate::upgrade::staging::read_receipt(&older_request).unwrap().unwrap();
            assert_eq!(older_first.first_receipt_ms, 1000);
            assert_eq!(older_first.chosen_delay, Duration::from_secs(3260));
            assert_eq!(older_first.manifest_sha256, older_request.manifest_sha256);

            let newer_injection = startup_release_seam::install(newer_release);
            let newer = run_startup_update_check(&config, None, Some(newer_runtime));
            tokio::pin!(newer);
            assert_eq!(staging_next_observation(newer.as_mut(), &mut newer_rx, deadline).await.unwrap(),
                crate::upgrade::staging::Decision::Waiting(Duration::from_secs(1276)));
            drop(newer_injection);
            let newer_first = crate::upgrade::staging::read_receipt(&newer_request).unwrap().unwrap();
            assert_eq!(newer_first.first_receipt_ms, 1000);
            assert_eq!(newer_first.chosen_delay, Duration::from_secs(1276));
            assert_eq!(newer_first.manifest_sha256, newer_request.manifest_sha256);
            assert_eq!(newer_first.archive_sha256, newer_request.archive_sha256);
            assert!(attempts.lock().unwrap().is_empty());
            assert_eq!(started.elapsed(), Duration::ZERO);
            assert!(apply_lock.try_lock().is_ok());

            // Keep B's actual future alive but do not poll it yet. A must be
            // refused by durable supersession, not by B having changed VERSION.
            tokio::time::advance(Duration::from_secs(3260)).await;
            let older_result = loop {
                match staging_next_observation(older.as_mut(), &mut older_rx, deadline).await {
                    Ok(crate::upgrade::staging::Decision::Due) => {}
                    Ok(other) => panic!("older due operation restarted its wait: {other:?}"),
                    Err(result) => break result,
                }
            };
            let attempts_before_newer_resume = attempts.lock().unwrap().clone();
            let newer_result = loop {
                match staging_next_observation(newer.as_mut(), &mut newer_rx, deadline).await {
                    Ok(crate::upgrade::staging::Decision::Due) => {}
                    Ok(other) => panic!("newer due operation restarted its wait: {other:?}"),
                    Err(result) => break result,
                }
            };
            // Complete both owned operations before reporting the intended RED.
            // On early assertion failure their pinned futures still drop before
            // the scoped readback/apply guards; no timer is detached by this test.
            assert!(matches!(&newer_result, Ok(Some(version)) if version == "9.9.10"), "{newer_result:?}");
            assert_eq!(attempts.lock().unwrap().iter().filter(|v| v.as_str() == "9.9.10").count(), 1);
            assert_eq!(std::fs::read(&install).unwrap(), original);
            assert!(apply_lock.try_lock().is_ok());
            assert!(matches!(&older_result, Ok(None)),
                "a durably newer receipt must refuse the older startup: {older_result:?}");
            assert!(attempts_before_newer_resume.is_empty(),
                "older startup reached destructive admission: {attempts_before_newer_resume:?}");
            assert_eq!(*attempts.lock().unwrap(), vec!["9.9.10".to_owned()]);
            let retained = crate::upgrade::staging::read_receipt(&older_request).unwrap().unwrap();
            assert_eq!(retained.first_receipt_ms, older_first.first_receipt_ms);
            assert_eq!(retained.chosen_delay, older_first.chosen_delay);
            assert_eq!(retained.manifest_sha256, older_request.manifest_sha256);
        }
    };
}
