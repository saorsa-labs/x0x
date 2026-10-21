// Expanded in routes::upgrade::tests. Existing seams supply a verified release,
// readback and download bytes; actual startup, journal barriers and guide writes
// run. The apply hook stops before archive download, candidate execution or swap.
#[allow(unused_macros)]
macro_rules! staging_guide_regression_tests {
    () => {
        #[cfg(unix)]
        mod staging_guide_regressions {
            use super::*;
            use crate::upgrade::{apply, journal, probe, staging};
            use sha2::Digest;
            use std::fs::{self, File, OpenOptions};
            use std::future::Future;
            use std::path::{Path, PathBuf};
            use std::pin::Pin;
            use std::sync::{Condvar, Mutex as StdMutex};
            use std::time::Instant;

            #[derive(Clone, Copy)]
            enum Cut {
                HoldAfterDue,
                Clean,
                CheckWriteLock,
                CancelWhileLocked,
                #[cfg(not(feature = "upgrade-test-signing"))]
                FleetIdentityAfterDue,
            }

            #[derive(Default)]
            struct Events {
                counts: StdMutex<(u64, u64)>,
                changed: Condvar,
                writes: AtomicU64,
                lock_result: AtomicU64,
            }

            struct Drain {
                shutdown: watch::Sender<bool>,
                held: Option<File>,
                events: Arc<Events>,
            }
            impl Drop for Drain {
                fn drop(&mut self) {
                    let _ = self.shutdown.send(true);
                    self.held.take();
                    let counts = self.events.counts.lock().unwrap();
                    let (counts, _) = self.events.changed.wait_timeout_while(
                        counts,
                        Duration::from_secs(20),
                        |(entered, exited)| entered != exited,
                    ).unwrap();
                    if !std::thread::panicking() {
                        assert_eq!(counts.0, counts.1, "actual guide worker did not exit");
                    }
                }
            }

            async fn finish<F: Future>(mut future: Pin<&mut F>, deadline: Instant) -> F::Output {
                loop {
                    assert!(Instant::now() < deadline, "actual startup did not drain");
                    tokio::select! { biased;
                        result = future.as_mut() => return result,
                        _ = tokio::task::yield_now() => {}
                    }
                }
            }

            // The production auxiliary writer performs write/file-sync/rename/
            // directory-sync. Its actual probe reader then validates this typed
            // fixture as a FailedHold; it is not execution-probe evidence.
            fn write_hold(install: &Path, manifest: &ReleaseManifest) -> (PathBuf, Vec<u8>) {
                let record = probe::ProbeState {
                    schema_version: 1,
                    record_kind: "probe".into(),
                    install: install.to_owned(),
                    version: manifest.version.clone(),
                    platform: manifest.assets[0].target.clone(),
                    archive_sha256: manifest.assets[0].archive_sha256,
                    transaction_id: "51515151-5151-4151-8151-515151515151".into(),
                    attempt: 1,
                    phase: probe::ProbePhase::FailedHold,
                    cause: Some(probe::ProbeCause::NonzeroExit),
                    last_pid: None,
                    boot_id: "guide-hold-fixture".into(),
                    retry_remaining_ms: 0,
                    retry_deadline_ms: 0,
                    daemon_sha256: None,
                    cli_sha256: None,
                };
                let path = probe::state_path(install).unwrap();
                journal::write_auxiliary_record(&path, &record, |bytes| {
                    serde_json::from_slice::<probe::ProbeState>(bytes)
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                }).unwrap();
                assert_eq!(probe::read_state(install).unwrap().unwrap().phase,
                    probe::ProbePhase::FailedHold);
                assert!(matches!(probe::inspect_admission(install, &manifest.version),
                    Err(probe::ProbeRefusal::Held { .. })));
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            }

            async fn run(cut: Cut) {
                #[cfg(not(feature = "upgrade-test-signing"))]
                let fresh_fleet_identity = matches!(cut, Cut::FleetIdentityAfterDue);
                #[cfg(feature = "upgrade-test-signing")]
                let fresh_fleet_identity = false;
                let deadline = Instant::now() + Duration::from_secs(30);
                let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning/upgrade-guide-fixtures"));
                fs::create_dir_all(&base).unwrap();
                let root = tempfile::Builder::new().prefix("guide-race-")
                    .tempdir_in(base).unwrap();
                let data = root.path().canonicalize().unwrap();
                let (mut runtime, shutdown) = e2e_startup_runtime(&data);
                let install = data.join("x0xd");
                let _raw = apply::current_binary_path_seam::install(install.clone());
                let installed = fs::read(&install).unwrap();
                let mut readback = Some(restart::systemd_readback_seam::install(staging_readback(
                    one_call_scenario("0", "5"), &runtime,
                )));
                let readback_api_addr = runtime.restart_context.api_addr;
                let mut tracked_scenario = if fresh_fleet_identity {
                    let authority: serde_json::Value = serde_json::from_str(include_str!(concat!(
                        env!("CARGO_MANIFEST_DIR"), "/.deployment/authority-inventory.json"
                    ))).unwrap();
                    let unit = Path::new(authority["instances"][0]["unit"]["destination"]
                        .as_str().unwrap()).file_name().unwrap().to_str().unwrap();
                    let mut scenario = staging_readback(one_call_scenario("0", "5"), &runtime);
                    scenario.cgroup = format!("0::/system.slice/{unit}");
                    Some(scenario)
                } else { None };
                let (observed, mut observations) = tokio::sync::mpsc::unbounded_channel();
                runtime.staging.observed = Some(Arc::new(move |decision| {
                    let _ = observed.send(decision);
                }));
                let guide = data.join("SKILL.md");
                let old = b"owned previous guide";
                let new = b"owned verified candidate guide".to_vec();
                fs::write(&guide, old).unwrap();
                let mut manifest = manifest_for_this_platform("9.9.9");
                manifest.timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                manifest.skill_url = "inert-guide://owned/download".into();
                manifest.skill_sha256 = sha2::Sha256::digest(&new).into();
                let raw_manifest = serde_json::to_vec(&manifest).unwrap();
                let request = staging::StagingRequest {
                    install: install.clone(), data_root: data.clone(), identity_root: data.clone(),
                    machine_id: [42; 32], version: manifest.version.clone(),
                    manifest_sha256: sha2::Sha256::digest(&raw_manifest).into(),
                    archive_sha256: manifest.assets[0].archive_sha256, window_minutes: 0,
                };
                let (started_tx, mut started) = tokio::sync::oneshot::channel();
                let (release_tx, release_rx) = tokio::sync::oneshot::channel();
                let downloaded = new.clone();
                let _download = skill_download_seam::install(async move {
                    let _ = started_tx.send(());
                    release_rx.await.unwrap();
                    downloaded
                });
                let attempts = Arc::new(AtomicU64::new(0));
                let attempted = Arc::clone(&attempts);
                let _apply = apply::apply_attempt_seam::install(Box::new(move |_, manifest| {
                    attempted.fetch_add(1, Ordering::SeqCst);
                    x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
                }));
                let _release = startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
                    manifest: manifest.clone(), manifest_json: raw_manifest,
                    signature: Vec::new(), gossip_payload: Vec::new(),
                });
                let events = Arc::new(Events::default());
                let observed_events = Arc::clone(&events);
                let lock_path = data.join("x0xd.upgrade.lock");
                let _writer = skill_install_seam::install(guide.clone(), Arc::new(move |event| {
                    use skill_install_seam::Event;
                    match event {
                        Event::Entered => observed_events.counts.lock().unwrap().0 += 1,
                        Event::Exited => {
                            observed_events.counts.lock().unwrap().1 += 1;
                            observed_events.changed.notify_all();
                        }
                        Event::BeforeWrite => {
                            observed_events.writes.fetch_add(1, Ordering::SeqCst);
                            // A distinct real file description tests writer lock
                            // custody. Drop immediately if the lock was missing.
                            let result = OpenOptions::new().read(true).write(true)
                                .open(&lock_path).map(|file| match file.try_lock() {
                                    Err(std::fs::TryLockError::WouldBlock) => 1,
                                    Ok(()) => 2,
                                    Err(_) => 3,
                                }).unwrap_or(3);
                            observed_events.lock_result.store(result, Ordering::SeqCst);
                        }
                    }
                }));
                let mut drain = Drain { shutdown: shutdown.clone(), held: None, events: Arc::clone(&events) };
                let mut config = DaemonConfig { data_dir: data.clone(), ..Default::default() };
                config.update.rollout_window_minutes = 0;
                let apply_lock = Arc::clone(&runtime.upgrade_apply_lock);
                let startup = run_startup_update_check(&config, None, Some(runtime));
                tokio::pin!(startup);
                loop {
                    assert!(Instant::now() < deadline, "download did not start");
                    tokio::select! { biased;
                        result = startup.as_mut() => panic!("startup finished before download: {result:?}"),
                        signal = &mut started => { signal.unwrap(); break; },
                        _ = tokio::task::yield_now() => {}
                    }
                }
                assert_eq!(observations.try_recv().unwrap(), staging::Decision::Due);
                let receipt = staging::receipt_path(&request).unwrap();
                let first_receipt = fs::read(&receipt).unwrap();
                if fresh_fleet_identity {
                    assert_eq!(staging::read_receipt(&request).unwrap().unwrap().window_minutes, 0);
                    // The download is still paused and the first identity
                    // worker has finished. Drop the old global guard FIRST;
                    // dropping it after install would erase the new scenario.
                    drop(readback.take());
                    readback = Some(restart::systemd_readback_seam::install(
                        tracked_scenario.take().unwrap(),
                    ));
                    // Validate the raw fixture through the production reader
                    // and floor policy: an invalid readback is not this proof.
                    let identity = restart::resolve_staging_identity(
                        true, &install, Some(&data), readback_api_addr, None,
                    ).await.unwrap();
                    let policy = crate::upgrade::fleet_policy::effective_staging_window(
                        0, &install, &identity,
                    ).unwrap();
                    assert_eq!(policy.minimum_window_minutes, 60);
                    assert_eq!(fs::read(&receipt).unwrap(), first_receipt);
                }
                let held_record = if matches!(cut, Cut::HoldAfterDue) {
                    let _lock = crate::upgrade::acquire_host_upgrade_lock(&install).unwrap();
                    Some(write_hold(&install, &manifest))
                } else { None };
                if matches!(cut, Cut::CancelWhileLocked) {
                    drain.held = Some(crate::upgrade::acquire_host_upgrade_lock(&install).unwrap());
                }
                release_tx.send(()).unwrap();
                if matches!(cut, Cut::CancelWhileLocked) {
                    while events.counts.lock().unwrap().0 == 0 {
                        assert!(Instant::now() < deadline, "guide worker did not enter");
                        tokio::select! { biased;
                            result = startup.as_mut() => panic!("startup ended before worker entry: {result:?}"),
                            _ = tokio::task::yield_now() => {}
                        }
                    }
                    shutdown.send(true).unwrap();
                    // Fixed-head custody control: the actual writer must wait
                    // behind C. Baseline can already have written by this point;
                    // no stable independent RED claim is made for cancellation.
                    let _ = finish(startup.as_mut(), deadline).await;
                    drain.held.take();
                } else {
                    let result = finish(startup.as_mut(), deadline).await;
                    if matches!(cut, Cut::Clean | Cut::CheckWriteLock) {
                        assert!(matches!(result, Ok(Some(ref version)) if version == "9.9.9"), "{result:?}");
                    }
                }
                // A completed startup may already have dropped its last
                // receiver. Any retained retry receiver must still see shutdown;
                // no receivers is valid cleanup, not a failed cancellation.
                let _ = shutdown.send(true);
                loop {
                    let (entered, exited) = *events.counts.lock().unwrap();
                    if entered == exited { break; }
                    assert!(Instant::now() < deadline, "actual guide worker did not exit");
                    tokio::task::yield_now().await;
                }
                loop {
                    if let Some(owner) = crate::upgrade::probe_retry::claim_retry(install.clone(), manifest.version.clone()) {
                        drop(owner); break;
                    }
                    assert!(Instant::now() < deadline, "startup retry owner did not drain");
                    tokio::task::yield_now().await;
                }
                assert_eq!(*events.counts.lock().unwrap(), (1, 1));
                assert_eq!(fs::read(&install).unwrap(), installed);
                assert!(apply_lock.try_lock().is_ok());
                assert!(!fs::read_dir(&data).unwrap().any(|entry| entry.unwrap()
                    .file_name().to_string_lossy().starts_with("SKILL.md.tmp.")));
                if matches!(cut, Cut::HoldAfterDue | Cut::CancelWhileLocked) || fresh_fleet_identity {
                    assert_eq!(fs::read(&guide).unwrap(), old, "no guide write may cross a current refusal");
                    assert_eq!(attempts.load(Ordering::SeqCst), 0);
                    assert_eq!(fs::read(receipt).unwrap(), first_receipt);
                    assert_eq!(events.writes.load(Ordering::SeqCst), 0);
                } else {
                    assert_eq!(fs::read(&guide).unwrap(), new);
                    assert_eq!(attempts.load(Ordering::SeqCst), 1);
                    assert_eq!(events.writes.load(Ordering::SeqCst), 1);
                }
                if let Some((path, bytes)) = held_record {
                    assert_eq!(fs::read(path).unwrap(), bytes, "durable hold must stay unchanged");
                }
                if matches!(cut, Cut::CheckWriteLock) {
                    assert_eq!(events.lock_result.load(Ordering::SeqCst), 1,
                        "actual write must hold the canonical install lock");
                }
                // Retain the current raw readback until all actual owned work
                // above has drained, including a scheduled refusal retry.
                drop(readback);
            }

            #[tokio::test(start_paused = true)]
            async fn staging_guide_hold_after_due_preserves_guide_and_hold() { run(Cut::HoldAfterDue).await; }
            #[tokio::test(start_paused = true)]
            async fn staging_guide_due_writes_once_and_applies_once() { run(Cut::Clean).await; }
            #[tokio::test(start_paused = true)]
            async fn staging_guide_actual_write_holds_canonical_install_lock() { run(Cut::CheckWriteLock).await; }
            #[tokio::test(start_paused = true)]
            async fn staging_guide_cancelled_before_install_drains_without_writes() { run(Cut::CancelWhileLocked).await; }

            #[cfg(not(feature = "upgrade-test-signing"))]
            #[tokio::test(start_paused = true)]
            async fn fleet_guide_fresh_identity_refuses_existing_zero_receipt_after_download() {
                run(Cut::FleetIdentityAfterDue).await;
            }
        }
    };
}
