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

        #[cfg(unix)]
        mod staging_preflight_regressions {
            use super::*;
            use crate::upgrade::{apply, probe, staging, staging_selection};
            use sha2::Digest;
            use std::{collections::BTreeMap, fs, future::Future, path::{Path, PathBuf}, sync::Mutex as StdMutex};

            struct Fixture {
                root: PathBuf,
                request: staging::StagingRequest,
                manifest: ReleaseManifest,
                upgrader: AutoApplyUpgrader,
                attempts: Arc<AtomicU64>,
                _apply: apply::apply_attempt_seam::Guard,
                _readback: restart::systemd_readback_seam::Guard,
                _raw: apply::current_binary_path_seam::Guard,
                _dir: tempfile::TempDir,
            }

            fn clock() -> probe::ProbeClock {
                probe::ProbeClock { boot_id: "preflight-receipt".into(), monotonic_ms: 1000 }
            }

            fn records(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
                fs::read_dir(root).unwrap().map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = fs::read(&path).unwrap();
                    (path, bytes)
                }).collect()
            }

            async fn complete<F: Future>(operation: F) -> F::Output {
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                tokio::pin!(operation);
                loop {
                    assert!(std::time::Instant::now() < deadline, "actual preflight worker did not finish");
                    tokio::select! { biased;
                        result = operation.as_mut() => return result,
                        _ = tokio::task::yield_now() => {}
                    }
                }
            }

            fn seed_interrupted(install: &Path, manifest: &ReleaseManifest) {
                let state = probe::ProbeState {
                    schema_version: 1, record_kind: "probe".into(), install: install.to_owned(),
                    version: manifest.version.clone(), platform: manifest.assets[0].target.clone(),
                    archive_sha256: manifest.assets[0].archive_sha256,
                    transaction_id: "15131513-1513-4513-8513-151315131513".into(), attempt: 1,
                    phase: probe::ProbePhase::InterruptedWait, cause: Some(probe::ProbeCause::Timeout),
                    last_pid: None, boot_id: "preflight-previous-boot".into(),
                    retry_remaining_ms: 1_800_000, retry_deadline_ms: 1_800_001,
                    daemon_sha256: None, cli_sha256: None,
                };
                assert_ne!(state.boot_id, probe::ProbeClock::now().unwrap().boot_id);
                fs::write(probe::state_path(install).unwrap(), serde_json::to_vec(&state).unwrap()).unwrap();
                // A typed fixture models retained state; no candidate is run.
                assert_eq!(probe::read_state(install).unwrap().unwrap().phase, probe::ProbePhase::InterruptedWait);
            }

            impl Fixture {
                fn new() -> Self {
                    let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                        .map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join(".planning/upgrade-staging-fixtures"));
                    fs::create_dir_all(&base).unwrap();
                    let dir = tempfile::Builder::new().prefix("preflight-selection-").tempdir_in(base).unwrap();
                    let root = dir.path().canonicalize().unwrap();
                    let (runtime, _shutdown) = e2e_startup_runtime(&root);
                    let raw = apply::current_binary_path_seam::install(root.join("x0xd"));
                    let readback = restart::systemd_readback_seam::install(staging_readback(
                        one_call_scenario("0", "5"), &runtime,
                    ));
                    let mut manifest = manifest_for_this_platform("9.9.9");
                    manifest.timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    let request = staging::StagingRequest {
                        install: root.join("x0xd"), data_root: root.clone(), identity_root: root.clone(),
                        machine_id: [42; 32], version: manifest.version.clone(),
                        manifest_sha256: sha2::Sha256::digest(serde_json::to_vec(&manifest).unwrap()).into(),
                        archive_sha256: manifest.assets[0].archive_sha256, window_minutes: 0,
                    };
                    {
                        let _held = crate::upgrade::acquire_host_upgrade_lock(&request.install).unwrap();
                        assert_eq!(staging_selection::observe_selected(&request, &clock()).unwrap(), staging::Decision::Due);
                    }
                    let upgrader = AutoApplyUpgrader::new("x0xd").with_stop_on_upgrade(true)
                        .with_restart_on_success(false).with_restart_context(runtime.restart_context)
                        .with_staging_request(request.clone())
                        .with_staging_clock(Some(Arc::new(|| Ok(clock()))));
                    let attempts = Arc::new(AtomicU64::new(0));
                    let counted = Arc::clone(&attempts);
                    let apply = apply::apply_attempt_seam::install(Box::new(move |_, manifest| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        // Stop before download, candidate execution, swap or restart.
                        x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
                    }));
                    Self { root, request, manifest, upgrader, attempts,
                        _apply: apply, _readback: readback, _raw: raw, _dir: dir }
                }

                fn newer(&self) -> staging::StagingRequest {
                    let mut manifest = self.manifest.clone();
                    manifest.version = "9.9.10".into();
                    staging::StagingRequest {
                        version: manifest.version.clone(),
                        manifest_sha256: sha2::Sha256::digest(serde_json::to_vec(&manifest).unwrap()).into(),
                        ..self.request.clone()
                    }
                }
            }

            async fn inter_worker_case(supersede: bool) {
                let fixture = Fixture::new();
                let selected = if supersede { fixture.newer() } else { fixture.request.clone() };
                let snapshot = Arc::new(StdMutex::new(None));
                let captured = Arc::clone(&snapshot);
                let calls = Arc::new(AtomicU64::new(0));
                let counted = Arc::clone(&calls);
                let root = fixture.root.clone();
                let manifest = fixture.manifest.clone();
                let expected_install = fixture.request.install.clone();
                let _cut = apply::pre_probe_admission_seam::install(expected_install.clone(), Box::new(move |install| {
                    assert_eq!(install, expected_install);
                    assert_eq!(counted.fetch_add(1, Ordering::SeqCst), 0);
                    // Nonblocking acquisition proves the first real Gate released
                    // this exact lock before the cut; no fixture thread can hang.
                    let held = fs::OpenOptions::new().read(true).write(true)
                        .open(root.join("x0xd.upgrade.lock")).unwrap();
                    held.try_lock().expect("first gate must release the canonical install lock");
                    assert_eq!(staging_selection::observe_selected(&selected, &clock()).unwrap(), staging::Decision::Due);
                    // Insert only after the first Gate: seeding it earlier would
                    // make that Gate acknowledge the clock and skip this cut.
                    seed_interrupted(install, &manifest);
                    *captured.lock().unwrap() = Some(records(&root));
                }));
                let result = complete(fixture.upgrader.apply_upgrade_from_manifest(&fixture.manifest)).await;
                // No detached retry is scheduled by this direct real apply path.
                // Both actual workers finish before snapshots or scoped hooks drop.
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
                let mut before = snapshot.lock().unwrap().take().unwrap();
                let mut after = records(&fixture.root);
                if supersede {
                    assert_eq!(after, before, "stale A must refuse before acknowledging its probe clock");
                    assert!(result.unwrap_err().to_string().contains("superseded"));
                } else {
                    let probe_path = probe::state_path(&fixture.request.install).unwrap();
                    assert_ne!(after.remove(&probe_path).unwrap(), before.remove(&probe_path).unwrap());
                    assert_eq!(after, before, "probe acknowledgement must not alter selection or receipts");
                    assert_eq!(probe::read_state(&fixture.request.install).unwrap().unwrap().boot_id,
                        probe::ProbeClock::now().unwrap().boot_id);
                    assert!(result.unwrap_err().to_string().contains("probe retry waits"));
                }
            }

            #[tokio::test]
            async fn staging_preflight_supersession_refuses_before_probe_clock_write() {
                inter_worker_case(true).await;
            }

            #[tokio::test]
            async fn staging_preflight_same_selection_reaches_actual_probe_clock_reader() {
                inter_worker_case(false).await;
            }

            #[tokio::test]
            async fn staging_direct_retry_preserves_stale_pending_and_unknown_selection() {
                for state in ["stale", "pending", "unknown", "valid"] {
                    let fixture = Fixture::new();
                    {
                        let _held = crate::upgrade::acquire_host_upgrade_lock(&fixture.request.install).unwrap();
                        match state {
                            "stale" => { staging_selection::observe_selected(&fixture.newer(), &clock()).unwrap(); }
                            "pending" => { fs::write(staging_selection::pending_path(&fixture.request).unwrap(), b"unresolved selection intent").unwrap(); }
                            "unknown" => {
                                let path = staging_selection::selection_path(&fixture.request).unwrap();
                                let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                                record["schema_version"] = serde_json::json!(999);
                                fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
                            }
                            "valid" => {}
                            _ => unreachable!(),
                        }
                        seed_interrupted(&fixture.request.install, &fixture.manifest);
                    }
                    let mut before = records(&fixture.root);
                    let result = complete(fixture.upgrader.probe_retry_delay(&fixture.manifest.version)).await;
                    let mut after = records(&fixture.root);
                    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
                    if state == "valid" {
                        let wait = result.unwrap().expect("selected A retains its actual probe retry");
                        assert_eq!(wait.transaction_id, "15131513-1513-4513-8513-151315131513");
                        assert!(!wait.delay.is_zero());
                        let path = probe::state_path(&fixture.request.install).unwrap();
                        assert_ne!(after.remove(&path).unwrap(), before.remove(&path).unwrap());
                        assert_eq!(probe::read_state(&fixture.request.install).unwrap().unwrap().boot_id,
                            probe::ProbeClock::now().unwrap().boot_id);
                    } else {
                        assert!(result.is_err(), "{state} selection must refuse direct retry");
                    }
                    assert_eq!(after, before, "{state}: retry must preserve retained evidence");
                }
            }
        }
    };
}

// Separately expanded inside upgrade::staging_selection after that real private
// implementation is registered. This does not alter the startup RED above.
#[allow(unused_macros)]
macro_rules! staging_selection_core_regression_tests {
    () => {
        #[cfg(unix)]
        mod staging_selection_regressions {
            use super::*;
            use std::{collections::BTreeMap, ffi::OsString, fs, time::Duration};

            struct Fixture {
                _dir: tempfile::TempDir,
                request: StagingRequest,
                _lock: fs::File,
            }

            impl Fixture {
                fn new() -> Self {
                    let evidence = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                                .join(".planning/upgrade-staging-fixtures")
                        });
                    fs::create_dir_all(&evidence).unwrap();
                    let dir = tempfile::Builder::new()
                        .prefix("selection-")
                        .tempdir_in(evidence)
                        .unwrap();
                    let root = dir.path().canonicalize().unwrap();
                    fs::write(root.join("x0xd"), b"owned selection install").unwrap();
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
                        window_minutes: 0,
                    };
                    let lock = crate::upgrade::acquire_host_upgrade_lock(&request.install).unwrap();
                    Self {
                        _dir: dir,
                        request,
                        _lock: lock,
                    }
                }
            }

            fn clock(ms: u64) -> ProbeClock {
                ProbeClock {
                    boot_id: "selection-fixture".into(),
                    monotonic_ms: ms,
                }
            }

            fn newer(request: &StagingRequest) -> StagingRequest {
                let mut next = request.clone();
                next.version = "1.2.4".into();
                next.manifest_sha256 = [5; 32];
                next.archive_sha256 = [6; 32];
                next
            }

            fn steps() -> [BarrierStep; 4] {
                [
                    BarrierStep::Write,
                    BarrierStep::FileSync,
                    BarrierStep::Rename,
                    BarrierStep::DirectorySync,
                ]
            }

            fn bytes(request: &StagingRequest) -> BTreeMap<OsString, Vec<u8>> {
                fs::read_dir(request.install.parent().unwrap())
                    .unwrap()
                    .map(|entry| entry.unwrap())
                    .filter(|entry| entry.path().is_file())
                    .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
                    .collect()
            }

            fn refuses_without_writes(request: &StagingRequest) {
                let before = bytes(request);
                assert!(check_request(&request.clone()).is_err());
                assert!(observe_selected(&request.clone(), &clock(1_000_000)).is_err());
                assert_eq!(
                    bytes(request),
                    before,
                    "fresh admission must preserve all owned record bytes"
                );
            }

            #[test]
            fn selection_fresh_reader_refuses_older_before_advancing_its_receipt() {
                let mut fixture = Fixture::new();
                fixture.request.window_minutes = 60;
                let old = fixture.request.clone();
                assert_eq!(
                    observe_selected(&old, &clock(1000)).unwrap(),
                    Decision::Waiting(Duration::from_secs(2532))
                );
                let old_path = staging::receipt_path(&old).unwrap();
                let old_bytes = fs::read(&old_path).unwrap();
                let next = newer(&old);
                assert!(matches!(
                    observe_selected(&next, &clock(1500)).unwrap(),
                    Decision::Waiting(_)
                ));
                let selected = read_selection(&next).unwrap().unwrap();
                assert_eq!(selected.release.version, "1.2.4");
                assert_eq!(selected.release.manifest_sha256, [5; 32]);
                assert_eq!(selected.release.archive_sha256, [6; 32]);
                assert_eq!(selected.supersedes.unwrap().version, "1.2.3");
                assert_eq!(
                    selection_path(&old).unwrap(),
                    selection_path(&next).unwrap()
                );
                assert_eq!(fs::read(&old_path).unwrap(), old_bytes);
                // Reconstruct the request and reread files; no stored in-memory
                // selection or process-local latch supplies refusal authority.
                refuses_without_writes(&old);
                assert_eq!(fs::read(old_path).unwrap(), old_bytes);
                check_request(&next).unwrap();
                observe_selected(&next, &clock(2000)).unwrap();
                assert_eq!(
                    staging::read_receipt(&next)
                        .unwrap()
                        .unwrap()
                        .first_receipt_ms,
                    1500
                );
            }

            #[test]
            fn selection_equal_precedence_version_strings_and_payloads_conflict() {
                let mut fixture = Fixture::new();
                fixture.request.version = "1.2.3+build.1".into();
                observe_selected(&fixture.request, &clock(1000)).unwrap();
                for field in ["version", "manifest", "archive"] {
                    let mut conflict = fixture.request.clone();
                    match field {
                        "version" => conflict.version = "1.2.3+build.2".into(),
                        "manifest" => conflict.manifest_sha256 = [9; 32],
                        _ => conflict.archive_sha256 = [9; 32],
                    }
                    assert_eq!(
                        selection_path(&conflict).unwrap(),
                        selection_path(&fixture.request).unwrap()
                    );
                    refuses_without_writes(&conflict);
                    if field == "version" {
                        assert!(!staging::receipt_path(&conflict).unwrap().exists());
                    }
                }
                assert_eq!(
                    observe_selected(&fixture.request, &clock(2000)).unwrap(),
                    Decision::Due
                );
            }

            #[test]
            fn selection_corrupt_unknown_or_unresolved_evidence_is_preserved() {
                let fixture = Fixture::new();
                let request = &fixture.request;
                observe_selected(request, &clock(1000)).unwrap();
                let path = selection_path(request).unwrap();
                let valid = fs::read(&path).unwrap();
                for field in [
                    "torn",
                    "schema_version",
                    "record_kind",
                    "extra",
                    "install",
                    "machine_id",
                    "supersedes",
                    "nested",
                ] {
                    let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
                    match field {
                        "schema_version" => value[field] = serde_json::json!(99),
                        "record_kind" => value[field] = serde_json::json!("unknown"),
                        "install" => value[field] = serde_json::json!("/different/owned-install"),
                        "machine_id" => value[field][0] = serde_json::json!(99),
                        "supersedes" => value[field] = value["release"].clone(),
                        "nested" => value["release"]["extra"] = serde_json::json!(true),
                        _ => value[field] = serde_json::json!(true),
                    }
                    let corrupt = if field == "torn" {
                        b"{torn".to_vec()
                    } else {
                        serde_json::to_vec(&value).unwrap()
                    };
                    fs::write(&path, &corrupt).unwrap();
                    refuses_without_writes(request);
                    assert_eq!(fs::read(&path).unwrap(), corrupt);
                }
                fs::write(&path, &valid).unwrap();
                let pending = pending_path(request).unwrap();
                for unresolved in [
                    b"{torn".as_slice(),
                    br#"{"schema_version":99,"record_kind":"rollout_selecting"}"#.as_slice(),
                ] {
                    fs::write(&pending, unresolved).unwrap();
                    refuses_without_writes(request);
                    refuses_without_writes(&newer(request));
                    assert_eq!(fs::read(&pending).unwrap(), unresolved);
                    assert_eq!(fs::read(&path).unwrap(), valid);
                }
                fs::remove_file(&pending).unwrap();
                fs::create_dir(&pending).unwrap();
                refuses_without_writes(request);
                assert!(
                    pending.is_dir(),
                    "unreadable record shape must not be erased"
                );
            }

            #[test]
            fn selection_receipt_barriers_precede_intent_and_require_a_real_retry() {
                for step in steps() {
                    let fixture = Fixture::new();
                    let old = &fixture.request;
                    observe_selected(old, &clock(1000)).unwrap();
                    let selected = fs::read(selection_path(old).unwrap()).unwrap();
                    let retained = fs::read(staging::receipt_path(old).unwrap()).unwrap();
                    let next = newer(old);
                    for _ in 0..2 {
                        assert!(observe_with_failure(
                            &next,
                            &clock(2000),
                            SelectionFailure::ReceiptBarrier(step)
                        )
                        .is_err());
                        assert_eq!(fs::read(selection_path(old).unwrap()).unwrap(), selected);
                        assert!(!pending_path(old).unwrap().exists());
                    }
                    // Before selection intent, failed B did not supersede A.
                    check_request(old).unwrap();
                    assert_eq!(
                        observe_selected(&next, &clock(2000)).unwrap(),
                        Decision::Due
                    );
                    refuses_without_writes(old);
                    assert_eq!(
                        fs::read(staging::receipt_path(old).unwrap()).unwrap(),
                        retained
                    );
                }
            }

            #[test]
            fn selection_intent_failure_cuts_preserve_the_last_acknowledged_choice() {
                for step in steps() {
                    let fixture = Fixture::new();
                    let old = &fixture.request;
                    observe_selected(old, &clock(1000)).unwrap();
                    let selected = fs::read(selection_path(old).unwrap()).unwrap();
                    let next = newer(old);
                    assert!(observe_with_failure(
                        &next,
                        &clock(2000),
                        SelectionFailure::IntentBarrier(step)
                    )
                    .is_err());
                    assert_eq!(fs::read(selection_path(old).unwrap()).unwrap(), selected);
                    if matches!(step, BarrierStep::DirectorySync) {
                        assert!(pending_path(old).unwrap().exists());
                        refuses_without_writes(old);
                        refuses_without_writes(&next);
                    } else {
                        assert!(!pending_path(old).unwrap().exists());
                        check_request(old).unwrap();
                        assert!(observe_with_failure(
                            &next,
                            &clock(2000),
                            SelectionFailure::IntentBarrier(step)
                        )
                        .is_err());
                        assert_eq!(
                            observe_selected(&next, &clock(2000)).unwrap(),
                            Decision::Due
                        );
                        refuses_without_writes(old);
                    }
                }
            }

            #[test]
            fn selection_failed_latest_record_or_unlink_leaves_intent_for_fresh_readers() {
                let failures = steps()
                    .map(SelectionFailure::SelectionBarrier)
                    .into_iter()
                    .chain([SelectionFailure::RemoveIntent]);
                for failure in failures {
                    let fixture = Fixture::new();
                    let old = &fixture.request;
                    observe_selected(old, &clock(1000)).unwrap();
                    let next = newer(old);
                    assert!(observe_with_failure(&next, &clock(2000), failure).is_err());
                    assert!(pending_path(old).unwrap().is_file());
                    assert!(staging::read_receipt(&next).unwrap().is_some());
                    let mut later = newer(&next);
                    later.version = "1.2.5".into();
                    for request in [old, &next, &later] {
                        refuses_without_writes(request);
                    }
                }
            }

            #[test]
            fn selection_absent_intent_after_failed_removal_sync_needs_both_barriers_again() {
                let fixture = Fixture::new();
                let old = &fixture.request;
                observe_selected(old, &clock(1000)).unwrap();
                let next = newer(old);
                assert!(observe_with_failure(
                    &next,
                    &clock(2000),
                    SelectionFailure::RemovalDirectorySync
                )
                .is_err());
                assert!(!pending_path(old).unwrap().exists());
                assert_eq!(
                    read_selection(&next).unwrap().unwrap().release.version,
                    "1.2.4"
                );
                refuses_without_writes(old);
                for step in steps() {
                    for failure in [
                        SelectionFailure::ReceiptBarrier(step),
                        SelectionFailure::SelectionBarrier(step),
                    ] {
                        assert!(observe_with_failure(&next, &clock(2000), failure).is_err());
                        assert!(!pending_path(old).unwrap().exists());
                        refuses_without_writes(old);
                    }
                }
                assert_eq!(
                    observe_selected(&next, &clock(2000)).unwrap(),
                    Decision::Due
                );
                // A diagnostic parse or prior success cannot skip a later ACK.
                assert!(observe_with_failure(
                    &next,
                    &clock(2000),
                    SelectionFailure::SelectionBarrier(BarrierStep::DirectorySync)
                )
                .is_err());
                assert_eq!(
                    observe_selected(&next, &clock(2000)).unwrap(),
                    Decision::Due
                );
            }

            #[test]
            fn selection_keeps_legacy_per_version_receipts_without_fabricating_prior_choice() {
                let mut fixture = Fixture::new();
                fixture.request.window_minutes = 60;
                let old = &fixture.request;
                staging::observe(old, &clock(1000)).unwrap();
                let older_path = staging::receipt_path(old).unwrap();
                let retained = fs::read(&older_path).unwrap();
                assert!(!selection_path(old).unwrap().exists());
                let next = newer(old);
                observe_selected(&next, &clock(2000)).unwrap();
                assert!(read_selection(&next).unwrap().unwrap().supersedes.is_none());
                assert_eq!(fs::read(&older_path).unwrap(), retained);
                refuses_without_writes(old);
                assert_eq!(fs::read(older_path).unwrap(), retained);
            }
        }
    };
}
