// Expanded inside upgrade::fleet_policy by the lead. The standalone integration
// target has no tests. These are private policy controls, not host inventory,
// service-manager verification, or proof that a real trigger enforces the policy.
#[allow(unused_macros)]
macro_rules! fleet_policy_regression_tests {
    () => {
        #[cfg(test)]
        mod fleet_policy_regressions {
            use super::*;

            fn verified(unit: &str, user_manager: bool) -> SystemdVerifiedUnit {
                SystemdVerifiedUnit {
                    unit: unit.into(), user_manager, restart: "always".into(), template_version: None,
                }
            }

            fn fixture() -> tempfile::TempDir {
                let root = std::env::var_os("X0X_UPGRADE_FLEET_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning/upgrade-fleet-fixtures"));
                std::fs::create_dir_all(&root).unwrap();
                tempfile::Builder::new().prefix("fleet-").tempdir_in(root).unwrap()
            }

            #[test]
            fn fleet_tracked_pairs_and_partial_signals_keep_the_production_floor() {
                let authority = parse_authority(AUTHORITY).unwrap();
                for entry in &authority {
                    let service = verified(&entry.unit, false);
                    assert_eq!(classify(&entry.binary, Some(&service), &authority), Classification::Fleet);
                    let user = verified(&entry.unit, true);
                    for (install, service) in [
                        (entry.binary.as_path(), None),
                        (entry.binary.as_path(), Some(&user)),
                        (Path::new("/owned-ordinary-fixture/x0xd"), Some(&service)),
                    ] {
                        assert_eq!(classify(install, service, &authority), Classification::AmbiguousFleet);
                    }
                }
                // Pure policy controls explicitly select the production rule.
                // They do not prove which key branch effective_window compiled.
                for classification in [Classification::Fleet, Classification::AmbiguousFleet] {
                    for (configured, expected) in [(0,60),(59,60),(60,60),(61,61),(u64::MAX,u64::MAX)] {
                        let actual = policy(configured, classification, false);
                        assert_eq!(actual.window_minutes, expected);
                        assert_eq!(actual.minimum_window_minutes, 60);
                    }
                }
            }

            #[test]
            fn fleet_ordinary_windows_and_explicit_rehearsal_policy_are_distinct() {
                let authority = parse_authority(AUTHORITY).unwrap();
                let service = verified("owned-untracked.service", false);
                let ordinary = classify(Path::new("/owned-ordinary-fixture/x0xd"), Some(&service), &authority);
                assert_eq!(ordinary, Classification::Ordinary);
                for configured in [0,1,59,60,u64::MAX] {
                    let ordinary = policy(configured, ordinary, false);
                    assert_eq!(ordinary.window_minutes, configured);
                    assert_eq!(ordinary.minimum_window_minutes, 0);
                    assert_eq!(policy(configured, Classification::Fleet, true).window_minutes, configured);
                }
            }

            // This invokes the real compile-time selector. The synthetic verified
            // plan is a policy input only; no manager, daemon or socket is started.
            fn assert_compiled_policy(expected_minimum: u64) {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let install = root.join("x0xd");
                std::fs::write(&install, b"owned policy fixture").unwrap();
                let authority = parse_authority(AUTHORITY).unwrap();
                let plan = RestartPlan {
                    mode: crate::upgrade::restart::RestartMode::SupervisedExit,
                    supervised_exit_code: Some(0), supervision_signal: Some("systemd".into()),
                    executable: install.clone(), argv: vec![install.to_str().unwrap().into()],
                    cwd: root.clone(), data_root: root,
                    api_addr: "127.0.0.1:1".parse().unwrap(), launchd_verified: None,
                    systemd_verified: Some(verified(&authority[0].unit, false)),
                };
                let actual = effective_window(0, &install, &plan).unwrap();
                assert_eq!(actual.classification, Classification::AmbiguousFleet);
                assert_eq!(actual.window_minutes, expected_minimum);
                assert_eq!(actual.minimum_window_minutes, expected_minimum);
                let mut mismatched = plan.clone();
                mismatched.executable = dir.path().join("another-binary");
                std::fs::write(&mismatched.executable, b"different owned file").unwrap();
                assert!(effective_window(0, &install, &mismatched).is_err());
                assert_eq!(std::fs::read(install).unwrap(), b"owned policy fixture");
            }

            // An --all-features build does NOT compile or execute this test.
            #[cfg(not(feature = "upgrade-test-signing"))]
            #[test]
            fn fleet_effective_window_uses_the_production_trust_branch() {
                assert_compiled_policy(60);
            }

            #[cfg(all(feature = "upgrade-test-signing", debug_assertions))]
            #[test]
            fn fleet_effective_window_waives_only_in_the_compiled_debug_test_key_branch() {
                assert_compiled_policy(0);
            }

            #[cfg(unix)]
            #[test]
            fn fleet_tracked_symlinks_remain_positive_and_uncertain_resolution_refuses() {
                use std::os::unix::fs::symlink;
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let target = root.join("real-x0xd");
                std::fs::write(&target, b"owned executable bytes").unwrap();
                let tracked = root.join("tracked-x0xd");
                symlink(&target, &tracked).unwrap();
                let entry = |binary| FleetAuthority {
                    binary, resolved_binary: None, unit: "owned-fleet.service".into(),
                };
                let resolved = resolve_authority(vec![entry(tracked.clone())]).unwrap();
                assert_eq!(classify(&target, None, &resolved), Classification::AmbiguousFleet);
                assert_eq!(classify(&target, Some(&verified("owned-fleet.service", false)), &resolved),
                    Classification::Fleet);
                let absent = resolve_authority(vec![entry(root.join("absent"))]).unwrap();
                assert!(absent[0].resolved_binary.is_none());
                assert_eq!(classify(&target, None, &absent), Classification::Ordinary);
                let uncertain = root.join("symlink-loop");
                symlink(&uncertain, &uncertain).unwrap();
                // ELOOP is deterministic even as root; chmod000 is not.
                assert!(resolve_authority(vec![entry(uncertain)]).is_err());
                assert_eq!(std::fs::read(target).unwrap(), b"owned executable bytes");
                assert_eq!(std::fs::read_link(tracked).unwrap(), root.join("real-x0xd"));
            }

            #[test]
            fn fleet_old_window_refuses_without_offering_a_replacement_receipt() {
                let enforced = policy(60, Classification::Fleet, false);
                for recorded in [0,1,59] {
                    assert_eq!(enforced.check_receipt_window(recorded).unwrap_err().kind(),
                        io::ErrorKind::PermissionDenied);
                }
                for recorded in [60,61,u64::MAX] {
                    enforced.check_receipt_window(recorded).unwrap();
                }
                // This guard receives only the frozen window, not chosen delay
                // or writable receipt state. Storage preservation is a separate
                // integration obligation; a legitimate chosen delay may be0.
                policy(0, Classification::Ordinary, false).check_receipt_window(0).unwrap();
                policy(0, Classification::Fleet, true).check_receipt_window(0).unwrap();
            }

            #[test]
            fn fleet_embedded_authority_rejects_unknown_or_ambiguous_inputs() {
                let original: serde_json::Value = serde_json::from_str(AUTHORITY).unwrap();
                let mut invalid = vec![serde_json::json!({"schema_version":1,"instances":[]})];
                for field in ["schema", "nested", "duplicate", "binary", "unit", "source", "selector"] {
                    let mut value = original.clone();
                    match field {
                        "schema" => value["schema_version"] = serde_json::json!(99),
                        "nested" => value["instances"][0]["binary"]["extra"] = serde_json::json!(true),
                        "duplicate" => {
                            let duplicate = value["instances"][0].clone();
                            value["instances"].as_array_mut().unwrap().push(duplicate);
                        }
                        "binary" => value["instances"][0]["binary"]["destination"] = serde_json::json!("/opt/../other"),
                        "unit" => value["instances"][0]["unit"]["destination"] = serde_json::json!("/etc/systemd/user/owned.service"),
                        "source" => value["instances"][0]["unit"]["source"] = serde_json::json!("../outside.service"),
                        _ => value["instances"][0]["installation"]["selector_args"] = serde_json::json!(["--instance","wrong"]),
                    }
                    invalid.push(value);
                }
                for value in invalid {
                    assert!(parse_authority(&serde_json::to_string(&value).unwrap()).is_err());
                }
                parse_authority(AUTHORITY).unwrap();
            }
        }
    };
}

// This separate macro compiles against the existing staged-startup baseline.
// Invoke in server::routes::upgrade::tests alongside staging_regression_tests.
// It uses only real existing release/readback/admission/clock seams.
#[allow(unused_macros)]
macro_rules! fleet_startup_regression_tests {
    () => {
        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        #[tokio::test(start_paused = true)]
        async fn fleet_production_startup_zero_config_still_uses_the_minimum_window() {
            fleet_first_receipt_case(false).await;
        }

        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        #[tokio::test(start_paused = true)]
        async fn fleet_production_pending_start_rate_keeps_the_first_receipt_minimum() {
            fleet_first_receipt_case(true).await;
        }

        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        async fn fleet_first_receipt_case(start_rate_pending: bool) {
            use sha2::Digest;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let evidence = std::env::var_os("X0X_UPGRADE_FLEET_EVIDENCE_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(".planning/upgrade-fleet-fixtures"));
            std::fs::create_dir_all(&evidence).unwrap();
            let dir = tempfile::Builder::new().prefix("fleet-startup-").tempdir_in(evidence).unwrap();
            let root = dir.path().canonicalize().unwrap();
            let (mut runtime, shutdown) = e2e_startup_runtime(&root);
            let _current_path = crate::upgrade::apply::current_binary_path_seam::install(
                root.join("x0xd"),
            );
            runtime.staging.machine_id = [42; 32];
            let install = runtime.staging.install.clone();
            let original = std::fs::read(&install).unwrap();
            let apply_lock = Arc::clone(&runtime.upgrade_apply_lock);
            let (observed, mut observations) = tokio::sync::mpsc::unbounded_channel();
            runtime.staging.observed = Some(Arc::new(move |decision| {
                observed.send(decision).unwrap();
            }));
            let started = tokio::time::Instant::now();
            runtime.staging.clock = Some(Arc::new(move || {
                Ok(crate::upgrade::probe::ProbeClock {
                    boot_id: "fleet-startup-fixture".into(),
                    monotonic_ms: 1000 + u64::try_from(started.elapsed().as_millis())
                        .map_err(std::io::Error::other)?,
                })
            }));
            let authority: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"), "/.deployment/authority-inventory.json"
            ))).unwrap();
            let unit = std::path::Path::new(authority["instances"][0]["unit"]["destination"]
                .as_str().unwrap()).file_name().unwrap().to_str().unwrap();
            let interval = if start_rate_pending { "10s" } else { "0" };
            let mut scenario = staging_readback(one_call_scenario(interval, "5"), &runtime);
            scenario.cgroup = format!("0::/system.slice/{unit}");
            let mut aged_out = staging_readback(one_call_scenario("10s", "5"), &runtime);
            aged_out.cgroup = scenario.cgroup.clone();
            aged_out.calls[0].monotonic_now_us = 15_000_000;
            let mut readback = Some(restart::systemd_readback_seam::install(scenario));
            let mut manifest = manifest_for_this_platform("9.9.9");
            manifest.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let manifest_json = serde_json::to_vec(&manifest).unwrap();
            let request = crate::upgrade::staging::StagingRequest {
                install: install.clone(), data_root: root.clone(),
                identity_root: runtime.staging.identity_root.clone(), machine_id: [42; 32],
                version: manifest.version.clone(),
                manifest_sha256: sha2::Sha256::digest(&manifest_json).into(),
                archive_sha256: manifest.assets[0].archive_sha256, window_minutes: 0,
            };
            let attempts = Arc::new(AtomicU64::new(0));
            let counted = Arc::clone(&attempts);
            let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |plan, manifest| {
                assert!(!plan.systemd_verified.as_ref().unwrap().user_manager);
                counted.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
            }));
            let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
                manifest, manifest_json, signature: Vec::new(), gossip_payload: Vec::new(),
            });
            let mut config = DaemonConfig { data_dir: root, ..Default::default() };
            config.update.rollout_window_minutes = 0;
            let mut startup = Box::pin(run_startup_update_check(&config, None, Some(runtime)));
            let mut next = match staging_next_observation(startup.as_mut(), &mut observations, deadline).await {
                Ok(decision) => decision,
                Err(result) => {
                    drop(startup);
                    // A refused identity schedules a real retry. Let its check
                    // finish before scoped raw readback/path guards are dropped.
                    loop {
                        if let Some(owner) = crate::upgrade::probe_retry::claim_retry(
                            install.clone(), "9.9.9".into(),
                        ) { drop(owner); break; }
                        assert!(std::time::Instant::now() < deadline, "retry check did not drain");
                        tokio::task::yield_now().await;
                    }
                    panic!("fleet must acknowledge its first window before admission: {result:?}");
                }
            };
            // Independently known [42;32]/9.9.9 fraction gives3260 seconds
            // for a60-minute window. The floor is not a minimum chosen delay.
            assert_eq!(next, crate::upgrade::staging::Decision::Waiting(Duration::from_secs(3260)));
            let receipt = crate::upgrade::staging::read_receipt(&request).unwrap().unwrap();
            assert_eq!(receipt.window_minutes, 60, "explicit fleet0 cannot freeze an undersized receipt");
            assert_eq!(receipt.first_receipt_ms, 1000);
            assert_eq!(attempts.load(Ordering::SeqCst), 0);
            assert!(apply_lock.try_lock().is_ok());
            if start_rate_pending {
                // The real readback still refuses restart, independently of
                // the staging-only identity used for the acknowledged receipt.
                let pending = restart::readback_systemd_policy(
                    &restart::SupervisionSignals::sample(), &install, &restart::current_argv(),
                );
                assert!(matches!(pending, restart::SystemdPolicyReadback::StartRateWindowPending {
                    retry_after, ..
                } if retry_after == Duration::from_secs(8)), "{pending:?}");
                assert_eq!(started.elapsed(), Duration::ZERO);
                assert_eq!(std::fs::read(&install).unwrap(), original);
                // One raw scenario repeats its pending result. Replace it only
                // after the first durable receipt; never drop an old guard
                // after installing the replacement, which would clear it.
                drop(readback.take());
                readback = Some(restart::systemd_readback_seam::install(aged_out));
            }
            let result = loop {
                if let crate::upgrade::staging::Decision::Waiting(wait) = next {
                    let step = wait.min(Duration::from_secs(30));
                    assert!(started.elapsed() + step <= Duration::from_secs(3600));
                    tokio::time::advance(step).await;
                }
                match staging_next_observation(startup.as_mut(), &mut observations, deadline).await {
                    Ok(decision) => next = decision,
                    Err(result) => break result,
                }
            };
            drop(startup);
            drop(shutdown);
            assert!(matches!(&result, Ok(Some(version)) if version == "9.9.9"), "{result:?}");
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            assert!(started.elapsed() >= Duration::from_secs(3260));
            assert!(started.elapsed() <= Duration::from_secs(3600));
            let retained = crate::upgrade::staging::read_receipt(&request).unwrap().unwrap();
            assert_eq!(retained.first_receipt_ms, receipt.first_receipt_ms);
            assert_eq!(retained.window_minutes, 60);
            assert_eq!(std::fs::read(install).unwrap(), original);
            drop(readback);
        }

        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        #[tokio::test(start_paused = true)]
        async fn fleet_production_startup_preserves_and_refuses_an_existing_zero_window_receipt() {
            fleet_existing_zero_receipt_case(true, true).await;
        }

        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        #[tokio::test(start_paused = true)]
        async fn fleet_production_undersized_receipt_refusal_preserves_interrupted_probe_bytes() {
            fleet_retained_retry_case(Some("undersized")).await;
        }

        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        #[tokio::test(start_paused = true)]
        async fn fleet_production_unresolved_records_refusal_preserves_interrupted_probe_bytes() {
            for barrier in ["journal", "pair"] {
                fleet_retained_retry_case(Some(barrier)).await;
            }
        }

        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        #[tokio::test(start_paused = true)]
        async fn fleet_production_valid_receipt_retry_acknowledges_old_boot_without_advancing_receipt() {
            fleet_retained_retry_case(None).await;
        }

        #[cfg(all(unix, not(feature = "upgrade-test-signing")))]
        async fn fleet_retained_retry_case(barrier: Option<&str>) {
            use crate::upgrade::{pair, probe, probe_retry, staging};
            use sha2::Digest;

            let evidence = std::env::var_os("X0X_UPGRADE_FLEET_EVIDENCE_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(".planning/upgrade-fleet-fixtures"));
            std::fs::create_dir_all(&evidence).unwrap();
            let dir = tempfile::Builder::new().prefix("fleet-retry-").tempdir_in(evidence).unwrap();
            let root = dir.path().canonicalize().unwrap();
            let (mut runtime, shutdown) = e2e_startup_runtime(&root);
            let _current_path = crate::upgrade::apply::current_binary_path_seam::install(root.join("x0xd"));
            let install = root.join("x0xd");
            let installed = std::fs::read(&install).unwrap();
            let apply_lock = Arc::clone(&runtime.upgrade_apply_lock);
            let acknowledged = Arc::new(AtomicU64::new(0));
            let observed = Arc::clone(&acknowledged);
            runtime.staging.observed = Some(Arc::new(move |_| { observed.fetch_add(1, Ordering::SeqCst); }));
            runtime.staging.clock = Some(Arc::new(|| Ok(probe::ProbeClock {
                boot_id: "fleet-retry-receipt".into(), monotonic_ms: 1000,
            })));
            let authority: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"), "/.deployment/authority-inventory.json"))).unwrap();
            let unit = std::path::Path::new(authority["instances"][0]["unit"]["destination"].as_str().unwrap())
                .file_name().unwrap().to_str().unwrap();
            let mut scenario = staging_readback(one_call_scenario("0", "5"), &runtime);
            scenario.cgroup = format!("0::/system.slice/{unit}");
            let _readback = restart::systemd_readback_seam::install(scenario);
            let mut manifest = manifest_for_this_platform("9.9.9");
            manifest.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let manifest_json = serde_json::to_vec(&manifest).unwrap();
            let request = staging::StagingRequest {
                install: install.clone(), data_root: root.clone(), identity_root: root.clone(),
                machine_id: [42; 32], version: manifest.version.clone(),
                manifest_sha256: sha2::Sha256::digest(&manifest_json).into(),
                archive_sha256: manifest.assets[0].archive_sha256,
                window_minutes: if barrier == Some("undersized") { 0 } else { 60 },
            };
            {
                let _held = crate::upgrade::acquire_host_upgrade_lock(&install).unwrap();
                let decision = staging::observe(&request, &probe::ProbeClock {
                    boot_id: "fleet-retry-receipt".into(), monotonic_ms: 500,
                }).unwrap();
                assert_eq!(matches!(decision, staging::Decision::Due), barrier == Some("undersized"));
            }
            let receipt_path = staging::receipt_path(&request).unwrap();
            let receipt_before = std::fs::read(&receipt_path).unwrap();
            let retry_ms = if barrier.is_some() { 1 } else { 1_800_000 };
            let state = probe::ProbeState {
                schema_version: 1, record_kind: "probe".into(), install: install.clone(),
                version: manifest.version.clone(), platform: manifest.assets[0].target.clone(),
                archive_sha256: manifest.assets[0].archive_sha256,
                transaction_id: "13131313-1313-4313-8313-131313131313".into(), attempt: 1,
                phase: probe::ProbePhase::InterruptedWait, cause: Some(probe::ProbeCause::Timeout),
                last_pid: None, boot_id: "fleet-retry-previous-boot".into(),
                retry_remaining_ms: retry_ms, retry_deadline_ms: retry_ms + 1,
                daemon_sha256: None, cli_sha256: None,
            };
            assert_ne!(state.boot_id, probe::ProbeClock::now().unwrap().boot_id);
            let probe_path = probe::state_path(&install).unwrap();
            std::fs::write(&probe_path, serde_json::to_vec(&state).unwrap()).unwrap();
            assert_eq!(probe::read_state(&install).unwrap().unwrap().phase, probe::ProbePhase::InterruptedWait);
            let probe_before = std::fs::read(&probe_path).unwrap();
            let blocked_path = match barrier {
                Some("journal") => Some(root.join(crate::upgrade::journal::JOURNAL_FILE_NAME)),
                Some("pair") => Some(pair::pair_pending_path(&install).unwrap()),
                _ => None,
            };
            if let Some(path) = &blocked_path { std::fs::write(path, b"corrupt retained intent").unwrap(); }
            let attempts = Arc::new(AtomicU64::new(0));
            let counted = Arc::clone(&attempts);
            let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |_, manifest| {
                counted.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
            }));
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            if barrier.is_some() {
                let version = manifest.version.clone();
                let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
                    manifest, manifest_json, signature: Vec::new(), gossip_payload: Vec::new(),
                });
                let mut config = DaemonConfig { data_dir: root.clone(), ..Default::default() };
                config.update.rollout_window_minutes = 0;
                let mut startup = Box::pin(run_startup_update_check(&config, None, Some(runtime)));
                let result = loop {
                    assert!(std::time::Instant::now() < deadline, "startup refusal did not finish");
                    tokio::select! { biased;
                        result = startup.as_mut() => break result,
                        _ = tokio::task::yield_now() => {}
                    }
                };
                drop(startup);
                // schedule_probe_retry claims synchronously before startup
                // returns. No await occurs before checking its actual claim.
                let claim = probe_retry::claim_retry(install.clone(), version.clone());
                let scheduled = claim.is_none();
                drop(claim);
                // Let the real waiter finish without cancelling a live check.
                // The baseline acknowledges the old boot, reaches refused apply,
                // then exits on the unchanged transaction. The fix refuses first.
                loop {
                    if let Some(owner) = probe_retry::claim_retry(install.clone(), version.clone()) {
                        drop(owner); break;
                    }
                    assert!(std::time::Instant::now() < deadline, "actual retry owner did not drain");
                    tokio::time::advance(Duration::from_millis(10)).await;
                    tokio::task::yield_now().await;
                }
                assert!(scheduled, "actual startup error path must own the retry check");
                assert!(matches!(result, Ok(None)), "{result:?}");
                assert_eq!(acknowledged.load(Ordering::SeqCst), 0);
                assert_eq!(std::fs::read(&probe_path).unwrap(), probe_before,
                    "{barrier:?}: retry must not acknowledge boot/progress after staging refuses");
            } else {
                // A valid fleet receipt may still be waiting. Retry inspection
                // must remain available without requiring rollout Due or writing
                // a receipt tick. This awaits the actual owned worker directly.
                let upgrader = AutoApplyUpgrader::new("x0xd")
                    .with_stop_on_upgrade(true)
                    .with_restart_context(runtime.restart_context)
                    .with_staging_request(request.clone());
                let operation = upgrader.probe_retry_delay(&manifest.version); tokio::pin!(operation);
                let pending = loop {
                    assert!(std::time::Instant::now() < deadline, "valid retry check did not finish");
                    tokio::select! { biased;
                        result = operation.as_mut() => break result.unwrap(),
                        _ = tokio::task::yield_now() => {}
                    }
                }.expect("valid receipt retains its probe retry");
                assert_eq!(pending.transaction_id, state.transaction_id);
                assert_ne!(std::fs::read(&probe_path).unwrap(), probe_before);
                assert_eq!(probe::read_state(&install).unwrap().unwrap().boot_id,
                    probe::ProbeClock::now().unwrap().boot_id);
            }
            // Both paths have completed their actual worker and any scheduled
            // retry owner before retained records and scoped hooks are dropped.
            drop(shutdown);
            assert_eq!(attempts.load(Ordering::SeqCst), 0);
            assert_eq!(std::fs::read(&receipt_path).unwrap(), receipt_before);
            if let Some(path) = blocked_path { assert_eq!(std::fs::read(path).unwrap(), b"corrupt retained intent"); }
            assert_eq!(std::fs::read(install).unwrap(), installed);
            assert!(apply_lock.try_lock().is_ok());
        }

        #[cfg(unix)]
        #[tokio::test(start_paused = true)]
        async fn fleet_ordinary_startup_keeps_explicit_zero_and_applies_without_waiting() {
            fleet_existing_zero_receipt_case(false, false).await;
        }

        #[cfg(all(unix, feature = "upgrade-test-signing", debug_assertions))]
        #[tokio::test(start_paused = true)]
        async fn fleet_compiled_rehearsal_startup_keeps_explicit_zero_and_applies_without_waiting() {
            fleet_existing_zero_receipt_case(true, false).await;
        }

        #[cfg(unix)]
        async fn fleet_existing_zero_receipt_case(tracked_unit: bool, must_refuse: bool) {
            use sha2::Digest;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let evidence = std::env::var_os("X0X_UPGRADE_FLEET_EVIDENCE_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(".planning/upgrade-fleet-fixtures"));
            std::fs::create_dir_all(&evidence).unwrap();
            let dir = tempfile::Builder::new().prefix("fleet-retained-").tempdir_in(evidence).unwrap();
            let root = dir.path().canonicalize().unwrap();
            let (mut runtime, _shutdown) = e2e_startup_runtime(&root);
            let _current_path = crate::upgrade::apply::current_binary_path_seam::install(
                root.join("x0xd"),
            );
            let install = runtime.staging.install.clone();
            let original = std::fs::read(&install).unwrap();
            let apply_lock = Arc::clone(&runtime.upgrade_apply_lock);
            let (observed, mut observations) = tokio::sync::mpsc::unbounded_channel();
            let acknowledged = Arc::new(AtomicU64::new(0));
            let observed_count = Arc::clone(&acknowledged);
            runtime.staging.observed = Some(Arc::new(move |decision| {
                observed_count.fetch_add(1, Ordering::SeqCst);
                observed.send(decision).unwrap();
            }));
            runtime.staging.clock = Some(Arc::new(|| Ok(crate::upgrade::probe::ProbeClock {
                boot_id: "fleet-retained-receipt".into(), monotonic_ms: 1000,
            })));
            let authority: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"), "/.deployment/authority-inventory.json"
            ))).unwrap();
            let tracked = std::path::Path::new(authority["instances"][0]["unit"]["destination"]
                .as_str().unwrap()).file_name().unwrap().to_str().unwrap();
            let unit = if tracked_unit { tracked } else { "owned-untracked-fleet-control.service" };
            assert!(!authority["instances"].as_array().unwrap().iter().any(|entry| {
                std::path::Path::new(entry["unit"]["destination"].as_str().unwrap())
                    .file_name().unwrap() == "owned-untracked-fleet-control.service"
            }));
            let mut scenario = staging_readback(one_call_scenario("0", "5"), &runtime);
            scenario.cgroup = format!("0::/system.slice/{unit}");
            let _readback = restart::systemd_readback_seam::install(scenario);
            let mut manifest = manifest_for_this_platform("9.9.9");
            manifest.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let manifest_json = serde_json::to_vec(&manifest).unwrap();
            let request = crate::upgrade::staging::StagingRequest {
                install: install.clone(), data_root: root.clone(),
                identity_root: runtime.staging.identity_root.clone(),
                machine_id: runtime.staging.machine_id, version: manifest.version.clone(),
                manifest_sha256: sha2::Sha256::digest(&manifest_json).into(),
                archive_sha256: manifest.assets[0].archive_sha256, window_minutes: 0,
            };
            // Create real valid prior state. Later startup must not silently
            // reset its first choice, nor advance it before checking the floor.
            {
                let _lock = crate::upgrade::acquire_host_upgrade_lock(&install).unwrap();
                assert_eq!(crate::upgrade::staging::observe(&request, &crate::upgrade::probe::ProbeClock {
                    boot_id: "fleet-retained-receipt".into(), monotonic_ms: 500,
                }).unwrap(), crate::upgrade::staging::Decision::Due);
            }
            let path = crate::upgrade::staging::receipt_path(&request).unwrap();
            let retained = std::fs::read(&path).unwrap();
            let initial = crate::upgrade::staging::read_receipt(&request).unwrap().unwrap();
            assert_eq!(initial.window_minutes, 0);
            assert_eq!(initial.first_receipt_ms, 500);
            assert_eq!(initial.manifest_sha256, request.manifest_sha256);
            assert_eq!(initial.archive_sha256, request.archive_sha256);
            let attempts = Arc::new(AtomicU64::new(0));
            let counted = Arc::clone(&attempts);
            let expected_unit = unit.to_owned();
            let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |plan, manifest| {
                let verified = plan.systemd_verified.as_ref().unwrap();
                assert_eq!(verified.unit, expected_unit);
                assert!(!verified.user_manager);
                counted.fetch_add(1, Ordering::SeqCst);
                x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
            }));
            let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
                manifest, manifest_json, signature: Vec::new(), gossip_payload: Vec::new(),
            });
            let mut config = DaemonConfig { data_dir: root, ..Default::default() };
            config.update.rollout_window_minutes = 0;
            let started = tokio::time::Instant::now();
            let startup = run_startup_update_check(&config, None, Some(runtime));
            tokio::pin!(startup);
            // Keep virtual time fixed while real blocking filesystem work runs.
            // A rewritten sixty-minute receipt is a failure, not a long timeout.
            let result = loop {
                assert!(std::time::Instant::now() < deadline, "retained fleet fixture deadline");
                tokio::select! {
                    biased;
                    result = startup.as_mut() => break result,
                    Some(decision) = observations.recv() => {
                        assert_eq!(decision, crate::upgrade::staging::Decision::Due,
                            "an old receipt must be refused, never reset into a fresh wait");
                    }
                    _ = tokio::task::yield_now() => {}
                }
            };
            if must_refuse {
                assert!(matches!(&result, Ok(None)), "fleet old-window refusal: {result:?}");
                assert_eq!(attempts.load(Ordering::SeqCst), 0);
                assert_eq!(acknowledged.load(Ordering::SeqCst), 0);
                assert_eq!(std::fs::read(path).unwrap(), retained,
                    "refusal must precede every receipt write, including anchor progress");
            } else {
                assert!(matches!(&result, Ok(Some(version)) if version == "9.9.9"), "{result:?}");
                assert_eq!(attempts.load(Ordering::SeqCst), 1);
                assert!(acknowledged.load(Ordering::SeqCst) > 0);
                let final_receipt = crate::upgrade::staging::read_receipt(&request).unwrap().unwrap();
                assert_eq!(final_receipt.window_minutes, 0);
                assert_eq!(final_receipt.first_receipt_ms, 500);
                assert_eq!(final_receipt.remaining, Duration::ZERO);
            }
            assert_eq!(started.elapsed(), Duration::ZERO);
            assert!(apply_lock.try_lock().is_ok());
            assert_eq!(std::fs::read(install).unwrap(), original);
        }
    };
}
