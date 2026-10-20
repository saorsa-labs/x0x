// Expanded inside routes::upgrade::tests. Actual helper/gate/record paths with
// owned files and verified-release input; no Agent, socket or signature claim.
#[allow(unused_macros)]
macro_rules! http_now_regression_tests {
    () => {
        #[cfg(unix)]
        mod http_now_regressions {
            use super::*;
            use crate::upgrade::{journal, pair, probe, staging, staging_selection};
            use sha2::Digest;
            use std::collections::BTreeMap;
            use std::future::Future;
            use std::pin::Pin;
            use tokio::sync::mpsc::{self, UnboundedReceiver};
            type Outcome = (AutoApplyUpgrader, Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError>);

            struct Fixture {
                runtime: HttpUpgradeRuntime,
                shutdown: Option<watch::Sender<bool>>,
                observed: UnboundedReceiver<staging::Decision>,
                operations: UnboundedReceiver<bool>,
                drained: std::sync::mpsc::Receiver<()>,
                attempts: Arc<AtomicU64>,
                wait_lock: Arc<Mutex<()>>,
                install: PathBuf, data: PathBuf, identity: PathBuf, window: u64,
                _readback: restart::systemd_readback_seam::Guard,
                _apply: crate::upgrade::apply::apply_attempt_seam::Guard,
                _root: tempfile::TempDir,
            }

            fn bytes(root: &std::path::Path) -> BTreeMap<PathBuf, Vec<u8>> {
                fn visit(root: &std::path::Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
                    for entry in std::fs::read_dir(root).unwrap() {
                        let entry = entry.unwrap();
                        if entry.file_type().unwrap().is_dir() { visit(&entry.path(), result); }
                        else { result.insert(entry.path(), std::fs::read(entry.path()).unwrap()); }
                    }
                }
                let mut result = BTreeMap::new(); visit(root, &mut result); result
            }

            impl Fixture {
                fn new(window: u64, fleet: bool) -> Self {
                    let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                        .map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join(".planning/upgrade-http-fixtures"));
                    std::fs::create_dir_all(&base).unwrap();
                    let root = tempfile::Builder::new().prefix("http-now-").tempdir_in(base).unwrap();
                    let data = root.path().join("data");
                    let identity = root.path().join("identity");
                    std::fs::create_dir(&data).unwrap(); std::fs::create_dir(&identity).unwrap();
                    let data = data.canonicalize().unwrap(); let identity = identity.canonicalize().unwrap();
                    let (mut startup, shutdown) = e2e_startup_runtime(&data);
                    startup.staging.identity_root = identity.clone();
                    let install = startup.staging.install.clone();
                    // Precreate the real persistent lock so preservation checks
                    // can compare every fixture file, including lock bytes.
                    drop(crate::upgrade::acquire_host_upgrade_lock(&install).unwrap());
                    let (observed_tx, observed) = mpsc::unbounded_channel();
                    startup.staging.observed = Some(Arc::new(move |decision| { let _ = observed_tx.send(decision); }));
                    let mut scenario = staging_readback(one_call_scenario("0", "5"), &startup);
                    if fleet {
                        let authority: serde_json::Value = serde_json::from_str(include_str!(concat!(
                            env!("CARGO_MANIFEST_DIR"), "/.deployment/authority-inventory.json"))).unwrap();
                        let unit = std::path::Path::new(authority["instances"][0]["unit"]["destination"].as_str().unwrap())
                            .file_name().unwrap().to_str().unwrap();
                        scenario.cgroup = format!("0::/system.slice/{unit}");
                    }
                    let readback = restart::systemd_readback_seam::install(scenario);
                    let attempts = Arc::new(AtomicU64::new(0)); let counted = Arc::clone(&attempts);
                    let expected_install = install.clone(); let expected_data = data.clone();
                    let apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |plan, manifest| {
                        assert_eq!(plan.executable, expected_install); assert_eq!(plan.data_root, expected_data);
                        counted.fetch_add(1, Ordering::SeqCst);
                        x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
                    }));
                    let (operation_tx, operations) = mpsc::unbounded_channel();
                    let (drained_tx, drained) = std::sync::mpsc::channel();
                    let wait_lock = Arc::new(Mutex::new(()));
                    let runtime = HttpUpgradeRuntime {
                        config: DaemonUpdateConfig { rollout_window_minutes: window, ..Default::default() },
                        restart_context: startup.restart_context, apply_lock: startup.upgrade_apply_lock,
                        shutdown: startup.shutdown_watch, staging: Some(startup.staging),
                        operation_observer: Some(Arc::new(move |entered| {
                            let _ = operation_tx.send(entered);
                            if !entered { let _ = drained_tx.send(()); }
                        })),
                        wait_slot: Arc::new(Arc::clone(&wait_lock).try_lock_owned().unwrap()),
                    };
                    Self { runtime, shutdown: Some(shutdown), observed, operations, drained, attempts, wait_lock,
                        install, data, identity, window, _readback: readback, _apply: apply, _root: root }
                }
                fn release(&self, version: &str) -> crate::upgrade::monitor::VerifiedRelease {
                    let mut manifest = manifest_for_this_platform(version);
                    manifest.timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    manifest.assets[0].archive_url = "http-owned-fixture://not-downloaded".into();
                    manifest.assets[0].signature_url = "http-owned-fixture://not-downloaded".into();
                    let mut raw = serde_json::to_vec(&manifest).unwrap(); raw.extend_from_slice(b" \n");
                    crate::upgrade::monitor::VerifiedRelease { manifest, manifest_json: raw, signature: vec![], gossip_payload: vec![] }
                }
                fn request(&self, release: &crate::upgrade::monitor::VerifiedRelease) -> staging::StagingRequest {
                    staging::StagingRequest {
                        install: self.install.clone(), data_root: self.data.clone(), identity_root: self.identity.clone(),
                        machine_id: [42;32], version: release.manifest.version.clone(),
                        manifest_sha256: sha2::Sha256::digest(&release.manifest_json).into(),
                        archive_sha256: release.manifest.assets[0].archive_sha256, window_minutes: self.window,
                    }
                }
                fn seed_probe(&self, release: &crate::upgrade::monitor::VerifiedRelease, phase: probe::ProbePhase) -> PathBuf {
                    let clock = probe::ProbeClock::now().unwrap();
                    let waiting = phase == probe::ProbePhase::InterruptedWait;
                    let state = probe::ProbeState {
                        schema_version: 1, record_kind: "probe".into(), install: self.install.clone(),
                        version: release.manifest.version.clone(), platform: release.manifest.assets[0].target.clone(),
                        archive_sha256: release.manifest.assets[0].archive_sha256,
                        transaction_id: "12121212-1212-4212-8212-121212121212".into(), attempt: 1, phase,
                        cause: match phase {
                            probe::ProbePhase::FailedHold => Some(probe::ProbeCause::NonzeroExit),
                            probe::ProbePhase::RecoveryFailed => Some(probe::ProbeCause::HoldWriteFailed),
                            probe::ProbePhase::InterruptedWait => Some(probe::ProbeCause::Timeout), _ => None,
                        }, last_pid: None, boot_id: clock.boot_id,
                        retry_remaining_ms: if waiting { 1_800_000 } else { 0 },
                        retry_deadline_ms: if waiting { clock.monotonic_ms + 1_800_000 } else { 0 },
                        daemon_sha256: None, cli_sha256: None,
                    };
                    let path = probe::state_path(&self.install).unwrap();
                    // Typed retained-state input for the actual reader. This is
                    // not claimed as proof that any candidate child executed.
                    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
                    assert_eq!(probe::read_state(&self.install).unwrap().unwrap().phase, phase);
                    path
                }
            }

            async fn finish<F: Future<Output=Outcome>>(mut operation: Pin<&mut F>)
                -> Result<x0x::upgrade::UpgradeResult, x0x::upgrade::UpgradeError> {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                loop {
                    assert!(std::time::Instant::now() < deadline, "actual HTTP helper did not finish");
                    tokio::select! { biased; (_, result) = operation.as_mut() => return result, _ = tokio::task::yield_now() => {} }
                }
            }
            async fn event<F: Future<Output=Outcome>, T>(mut operation: Pin<&mut F>, events: &mut UnboundedReceiver<T>) -> T {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                loop {
                    assert!(std::time::Instant::now() < deadline, "actual HTTP event missing");
                    tokio::select! { biased;
                        event = events.recv() => return event.expect("event source closed"),
                        (_, result) = operation.as_mut() => panic!("HTTP ended before event: {result:?}"),
                        _ = tokio::task::yield_now() => {}
                    }
                }
            }

            #[tokio::test(start_paused = true)]
            async fn http_now_skips_delay_but_keeps_the_frozen_receipt_and_raw_release_binding() {
                let f = Fixture::new(60, false); let release = f.release("9.9.9"); let request = f.request(&release);
                let before = tokio::time::Instant::now();
                let operation = apply_http_release(&f.runtime, &release, true); tokio::pin!(operation);
                assert!(matches!(finish(operation.as_mut()).await, Ok(x0x::upgrade::UpgradeResult::Success { .. })));
                assert_eq!(before.elapsed(), Duration::ZERO); assert_eq!(f.attempts.load(Ordering::SeqCst), 1);
                let receipt = staging::read_receipt(&request).unwrap().unwrap();
                assert_eq!(receipt.window_minutes, 60); assert_eq!(receipt.chosen_delay, Duration::from_secs(3260));
                assert_eq!(receipt.remaining, receipt.chosen_delay); assert_eq!(receipt.first_receipt_ms, 1000);
                assert_eq!(receipt.manifest_sha256, request.manifest_sha256);
                let selected = staging_selection::read_selection(&request).unwrap().unwrap();
                assert_eq!(selected.release.manifest_sha256, request.manifest_sha256);
                assert_eq!(std::fs::read(&f.install).unwrap(), b"owned startup staging executable fixture");
            }

            #[cfg(not(feature="upgrade-test-signing"))]
            #[tokio::test(start_paused = true)]
            async fn http_now_production_fleet_refuses_existing_undersized_receipt_without_reset() {
                let f = Fixture::new(0, true); let release = f.release("9.9.9"); let request = f.request(&release);
                { let _lock = crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                  assert_eq!(staging::observe(&request, &probe::ProbeClock { boot_id:"startup-fixture".into(), monotonic_ms:1000 }).unwrap(), staging::Decision::Due); }
                let before = bytes(f._root.path());
                let operation = apply_http_release(&f.runtime, &release, true); tokio::pin!(operation);
                assert!(finish(operation.as_mut()).await.is_err());
                assert_eq!(bytes(f._root.path()), before); assert_eq!(f.attempts.load(Ordering::SeqCst), 0);
            }

            #[tokio::test(start_paused = true)]
            async fn http_now_refuses_eligibility_failures_before_any_receipt_or_apply() {
                for fault in ["stale", "old", "platform", "semver"] {
                    let f = Fixture::new(60, false); let mut release = f.release("9.9.9");
                    match fault { "stale" => release.manifest.timestamp=1, "old" => release.manifest.version="0.0.1".into(),
                        "platform" => release.manifest.assets.clear(), _ => release.manifest.version="invalid-version".into() }
                    release.manifest_json=serde_json::to_vec(&release.manifest).unwrap();
                    let before=bytes(f._root.path());
                    let operation=apply_http_release(&f.runtime,&release,true); tokio::pin!(operation);
                    let result=finish(operation.as_mut()).await;
                    assert!(!matches!(result,Ok(x0x::upgrade::UpgradeResult::Success{..})), "{fault}: {result:?}");
                    assert_eq!(f.attempts.load(Ordering::SeqCst),0,"{fault}"); assert_eq!(bytes(f._root.path()),before,"{fault}");
                }
            }

            #[tokio::test(start_paused = true)]
            async fn http_now_preserves_corrupt_records_pending_transactions_and_probe_holds() {
                for kind in ["journal", "handoff", "pair", "pair-pending", "selection", "selecting", "probe", "probe-pending", "failed", "recovery", "running"] {
                    let f=Fixture::new(60,false); let release=f.release("9.9.9");
                    let path=match kind {
                        "journal" => f.data.join(journal::JOURNAL_FILE_NAME), "handoff" => f.data.join(journal::HANDOFF_FILE_NAME),
                        "pair" => pair::pair_record_path(&f.install).unwrap(), "pair-pending" => pair::pair_pending_path(&f.install).unwrap(),
                        "selection" => staging_selection::selection_path(&f.request(&release)).unwrap(),
                        "selecting" => staging_selection::pending_path(&f.request(&release)).unwrap(),
                        "probe" => probe::state_path(&f.install).unwrap(), "probe-pending" => probe::uncertainty_path(&f.install).unwrap(),
                        "failed" => f.seed_probe(&release,probe::ProbePhase::FailedHold),
                        "recovery" => f.seed_probe(&release,probe::ProbePhase::RecoveryFailed),
                        _ => f.seed_probe(&release,probe::ProbePhase::Running),
                    };
                    if !path.exists() { std::fs::write(&path,b"{unknown or torn record").unwrap(); }
                    let before=bytes(f._root.path());
                    let operation=apply_http_release(&f.runtime,&release,true); tokio::pin!(operation);
                    assert!(finish(operation.as_mut()).await.is_err(),"{kind}");
                    assert_eq!(f.attempts.load(Ordering::SeqCst),0,"{kind}"); assert_eq!(bytes(f._root.path()),before,"{kind}");
                }
            }

            #[tokio::test(start_paused = true)]
            async fn http_now_keeps_probe_retry_wait_and_releases_apply_mutex() {
                let mut f=Fixture::new(60,false); let release=f.release("9.9.9"); let request=f.request(&release);
                f.seed_probe(&release,probe::ProbePhase::InterruptedWait);
                let operation=apply_http_release(&f.runtime,&release,true); tokio::pin!(operation);
                let decision=event(operation.as_mut(),&mut f.observed).await;
                let staging::Decision::Waiting(wait)=decision else { panic!("now bypassed probe retry"); };
                assert!(wait>Duration::from_secs(1700) && wait<=Duration::from_secs(1800));
                assert!(f.runtime.apply_lock.try_lock().is_ok()); assert_eq!(f.attempts.load(Ordering::SeqCst),0);
                assert_eq!(staging::read_receipt(&request).unwrap().unwrap().remaining,Duration::from_secs(3260));
                f.shutdown.as_ref().unwrap().send(true).unwrap(); assert!(finish(operation.as_mut()).await.is_err());
                assert_eq!(probe::read_state(&f.install).unwrap().unwrap().phase,probe::ProbePhase::InterruptedWait);
            }

            #[tokio::test(start_paused = true)]
            async fn http_now_preserves_supersession_and_failed_selection_barrier_evidence() {
                for pending in [false,true] {
                    let f=Fixture::new(60,false); let old=f.release("9.9.9"); let newer=f.release("9.9.10");
                    let old_request=f.request(&old); let new_request=f.request(&newer);
                    { let _lock=crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                      let clock=probe::ProbeClock {boot_id:"startup-fixture".into(),monotonic_ms:1000};
                      staging_selection::observe_selected(&old_request,&clock).unwrap();
                      if pending { assert!(staging_selection::observe_with_failure(&new_request,&clock,
                          staging_selection::SelectionFailure::SelectionBarrier(journal::BarrierStep::DirectorySync)).is_err()); }
                      else { staging_selection::observe_selected(&new_request,&clock).unwrap(); } }
                    // A stale selection must refuse before even advancing an
                    // independently retained probe retry clock.
                    f.seed_probe(&old,probe::ProbePhase::InterruptedWait);
                    let before=bytes(f._root.path());
                    for release in if pending { vec![&old,&newer] } else { vec![&old] } {
                        let operation=apply_http_release(&f.runtime,release,true); tokio::pin!(operation);
                        assert!(finish(operation.as_mut()).await.is_err()); assert_eq!(bytes(f._root.path()),before);
                    }
                    assert_eq!(f.attempts.load(Ordering::SeqCst),0);
                    assert!(staging::read_receipt(&old_request).unwrap().is_some());
                }
            }

            #[tokio::test(start_paused = true)]
            async fn http_now_rechecks_selection_and_holds_after_waiting_for_the_apply_mutex() {
                for superseded in [false,true] {
                    let mut f=Fixture::new(60,false); let old=f.release("9.9.9");
                    let held=Arc::clone(&f.runtime.apply_lock).lock_owned().await;
                    let operation=apply_http_release(&f.runtime,&old,true); tokio::pin!(operation);
                    assert_eq!(event(operation.as_mut(),&mut f.observed).await,staging::Decision::Due);
                    assert_eq!(f.attempts.load(Ordering::SeqCst),0);
                    { let _lock=crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                      if superseded {
                          let newer=f.release("9.9.10");
                          staging_selection::observe_selected(&f.request(&newer),&probe::ProbeClock {
                              boot_id:"startup-fixture".into(),monotonic_ms:1000,
                          }).unwrap();
                      } else { f.seed_probe(&old,probe::ProbePhase::FailedHold); } }
                    let before=bytes(f._root.path()); drop(held);
                    assert!(finish(operation.as_mut()).await.is_err());
                    assert_eq!(f.attempts.load(Ordering::SeqCst),0); assert_eq!(bytes(f._root.path()),before);
                }
            }

            #[tokio::test(start_paused = true)]
            async fn http_wait_cancellation_preserves_acknowledged_receipt_bytes() {
                for closed in [false,true] {
                    let mut f=Fixture::new(60,false); let release=f.release("9.9.9");
                    let operation=apply_http_release(&f.runtime,&release,false); tokio::pin!(operation);
                    assert!(matches!(event(operation.as_mut(),&mut f.observed).await,staging::Decision::Waiting(_)));
                    let before=bytes(f._root.path());
                    if closed { drop(f.shutdown.take()); } else { f.shutdown.as_ref().unwrap().send(true).unwrap(); }
                    assert!(finish(operation.as_mut()).await.is_err());
                    assert_eq!(bytes(f._root.path()),before); assert_eq!(f.attempts.load(Ordering::SeqCst),0);
                }
            }

            struct QueuedDrain {
                held: Option<std::fs::File>,
                done: std::sync::mpsc::Receiver<()>,
            }
            impl Drop for QueuedDrain {
                fn drop(&mut self) {
                    drop(self.held.take());
                    // Runs before fixture/global-hook destruction on failure.
                    let _ = self.done.recv_timeout(Duration::from_secs(6));
                }
            }

            #[tokio::test(start_paused = true)]
            async fn http_cancelled_queued_worker_retains_wait_slot_until_actual_exit_without_writes() {
                for drop_request in [false,true] {
                    let mut f=Fixture::new(60,false); let release=f.release("9.9.9");
                    let held=crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                    let before=bytes(f._root.path());
                    let mut drain=QueuedDrain {held:Some(held),done:f.drained};
                    let entered; let mut cancellation_refused=true;
                    { let mut operation=Box::pin(apply_http_release(&f.runtime,&release,false));
                      entered=event(operation.as_mut(),&mut f.operations).await;
                      if !drop_request { f.shutdown.as_ref().unwrap().send(true).unwrap(); cancellation_refused=finish(operation.as_mut()).await.is_err(); }
                    }
                    // Remove the request/runtime lease. Only the real queued
                    // closure may retain admission capacity from this point.
                    drop(f.runtime);
                    let capacity_retained=Arc::clone(&f.wait_lock).try_lock_owned().is_err();
                    let queued_bytes=bytes(f._root.path()); drop(drain.held.take());
                    let deadline=std::time::Instant::now()+Duration::from_secs(20);
                    loop {
                        assert!(std::time::Instant::now()<deadline,"cancelled queued worker did not drain");
                        if let Ok(exited)=f.operations.try_recv() { assert!(!exited); break; }
                        tokio::task::yield_now().await;
                    }
                    loop {
                        if let Ok(slot)=Arc::clone(&f.wait_lock).try_lock_owned() { drop(slot); break; }
                        assert!(std::time::Instant::now()<deadline,"worker retained wait slot after exit");
                        tokio::task::yield_now().await;
                    }
                    drop(drain);
                    assert!(entered); assert!(cancellation_refused); assert!(capacity_retained);
                    assert_eq!(queued_bytes,before);
                    assert_eq!(bytes(f._root.path()),before); assert_eq!(f.attempts.load(Ordering::SeqCst),0);
                }
            }
        }
    };
}
