// Expanded inside routes::upgrade::tests. These are actual HTTP helper and
// restart readback workers. Existing manager fixtures prevent subprocess I/O;
// the new hook only observes/pauses the real blocking closure.
#[allow(unused_macros)]
macro_rules! http_readback_regression_tests {
    () => {
        #[cfg(unix)]
        mod http_readback_regressions {
            use super::*;
            use crate::upgrade::restart::{readback_custody_seam, ReadbackKind};
            use readback_custody_seam::ReadbackEvent;
            use std::collections::BTreeMap;
            use std::sync::{atomic::{AtomicBool, AtomicUsize}, mpsc, Condvar, Mutex as StdMutex};
            use tokio::sync::mpsc as async_mpsc;

            struct Fixture {
                runtime: Option<HttpUpgradeRuntime>,
                wait_lock: Arc<Mutex<()>>,
                attempts: Arc<AtomicU64>,
                install: PathBuf,
                _shutdown: watch::Sender<bool>,
                _readback: restart::systemd_readback_seam::Guard,
                _apply: crate::upgrade::apply::apply_attempt_seam::Guard,
                _current_path: crate::upgrade::apply::current_binary_path_seam::Guard,
                root: tempfile::TempDir,
            }

            impl Fixture {
                fn new() -> Self {
                    let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                        .map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join(".planning/upgrade-http-readback-fixtures"));
                    std::fs::create_dir_all(&base).unwrap();
                    let root = tempfile::Builder::new().prefix("readback-").tempdir_in(base).unwrap();
                    let data = root.path().canonicalize().unwrap();
                    let (startup, shutdown) = e2e_startup_runtime(&data);
                    let current_path = crate::upgrade::apply::current_binary_path_seam::install(
                        data.join("x0xd"),
                    );
                    let install = startup.staging.install.clone();
                    drop(crate::upgrade::acquire_host_upgrade_lock(&install).unwrap());
                    let readback = restart::systemd_readback_seam::install(
                        staging_readback(one_call_scenario("0", "5"), &startup));
                    let attempts = Arc::new(AtomicU64::new(0));
                    let observed_attempts = Arc::clone(&attempts);
                    let apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |_, manifest| {
                        observed_attempts.fetch_add(1, Ordering::SeqCst);
                        x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
                    }));
                    let wait_lock = Arc::new(Mutex::new(()));
                    let runtime = HttpUpgradeRuntime {
                        config: DaemonUpdateConfig { rollout_window_minutes: 0, ..Default::default() },
                        restart_context: startup.restart_context, apply_lock: startup.upgrade_apply_lock,
                        wait_slot: Arc::new(Arc::clone(&wait_lock).try_lock_owned().unwrap()),
                        shutdown: startup.shutdown_watch, staging: Some(startup.staging), operation_observer: None,
                    };
                    Self { runtime: Some(runtime), wait_lock, attempts, install,
                        _shutdown: shutdown, _readback: readback, _apply: apply,
                        _current_path: current_path, root }
                }

                fn release() -> VerifiedRelease {
                    let mut manifest = manifest_for_this_platform("9.9.9");
                    manifest.timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                    VerifiedRelease { manifest_json: serde_json::to_vec(&manifest).unwrap(), manifest,
                        signature: vec![], gossip_payload: vec![] }
                }
            }

            fn bytes(root: &std::path::Path) -> BTreeMap<PathBuf, Vec<u8>> {
                let mut result = BTreeMap::new();
                for entry in std::fs::read_dir(root).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_type().unwrap().is_dir() { result.extend(bytes(&entry.path())); }
                    else { result.insert(entry.path(), std::fs::read(entry.path()).unwrap()); }
                }
                result
            }

            struct Shared {
                release: (StdMutex<bool>, Condvar),
                queued: AtomicUsize,
                exited: AtomicUsize,
                blockers: AtomicUsize,
                blockers_exited: AtomicUsize,
                launched: AtomicUsize,
                target_entered: AtomicBool,
                expired: AtomicBool,
                changed: mpsc::Sender<()>,
            }

            impl Shared {
                fn new() -> (Arc<Self>, mpsc::Receiver<()>) {
                    let (changed, receiver) = mpsc::channel();
                    (Arc::new(Self {
                        release: (StdMutex::new(false), Condvar::new()), queued: AtomicUsize::new(0),
                        exited: AtomicUsize::new(0), blockers: AtomicUsize::new(0), blockers_exited: AtomicUsize::new(0),
                        launched: AtomicUsize::new(0), target_entered: AtomicBool::new(false),
                        expired: AtomicBool::new(false), changed,
                    }), receiver)
                }
                fn pause(&self) {
                    let open = self.release.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let (open, _) = self.release.1.wait_timeout_while(open, Duration::from_secs(12), |open| !*open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if !*open { self.expired.store(true, Ordering::SeqCst); }
                }
                fn block_pool(self: &Arc<Self>, handle: &tokio::runtime::Handle) {
                    self.blockers.fetch_add(1, Ordering::SeqCst);
                    let shared = Arc::clone(self);
                    // This owned fixture occupies the single blocking worker.
                    // It runs no readback, filesystem or network operation.
                    handle.spawn_blocking(move || {
                        shared.pause();
                        shared.blockers_exited.fetch_add(1, Ordering::SeqCst);
                        let _ = shared.changed.send(());
                    });
                }
            }

            struct Drain {
                shared: Arc<Shared>,
                changed: mpsc::Receiver<()>,
            }
            impl Drain {
                fn release_and_drain(&self) -> bool {
                    *self.shared.release.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                    self.shared.release.1.notify_all();
                    let deadline = std::time::Instant::now() + Duration::from_secs(6);
                    loop {
                        if self.shared.exited.load(Ordering::SeqCst) >= self.shared.queued.load(Ordering::SeqCst)
                            && self.shared.blockers_exited.load(Ordering::SeqCst) >= self.shared.blockers.load(Ordering::SeqCst)
                        { return true; }
                        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else { return false; };
                        if self.changed.recv_timeout(remaining).is_err() { return false; }
                    }
                }
            }
            impl Drop for Drain {
                fn drop(&mut self) { let _ = self.release_and_drain(); }
            }

            fn cancellation_case(target: ReadbackKind, queued: bool, launchd_occurrence: usize) {
                let executor = tokio::runtime::Builder::new_current_thread().enable_all()
                    .max_blocking_threads(1).build().unwrap();
                executor.block_on(async {
                    let mut fixture = Fixture::new();
                    let release = Fixture::release();
                    let (shared, changed_rx) = Shared::new();
                    let (events_tx, mut events) = async_mpsc::unbounded_channel();
                    let hook_shared = Arc::clone(&shared);
                    let handle = tokio::runtime::Handle::current();
                    let hook_handle = handle.clone();
                    let hook = readback_custody_seam::install(fixture.install.clone(), Arc::new(move |kind, event| {
                        match event {
                            ReadbackEvent::Queued => { hook_shared.queued.fetch_add(1, Ordering::SeqCst); }
                            ReadbackEvent::Exited => {
                                hook_shared.exited.fetch_add(1, Ordering::SeqCst);
                                let _ = hook_shared.changed.send(());
                            }
                            ReadbackEvent::Entered => {
                                if kind == ReadbackKind::Launchd {
                                    let ordinal = hook_shared.launched.fetch_add(1, Ordering::SeqCst) + 1;
                                    if queued && target == ReadbackKind::SystemdPolicy && ordinal == 2 {
                                        // Enqueued while final launchd owns the only pool
                                        // thread, before the final systemd job is submitted.
                                        hook_shared.block_pool(&hook_handle);
                                    }
                                }
                                if kind == target && (kind != ReadbackKind::Launchd
                                    || hook_shared.launched.load(Ordering::SeqCst) == launchd_occurrence) {
                                    hook_shared.target_entered.store(true, Ordering::SeqCst);
                                    let _ = events_tx.send((kind, event));
                                    if !queued { hook_shared.pause(); }
                                    return;
                                }
                                if kind == target { return; }
                            }
                        }
                        let _ = events_tx.send((kind, event));
                    }));
                    // Declared after fixture and both hooks: panic cleanup must
                    // release/drain real workers before their inputs disappear.
                    let drain = Drain { shared: Arc::clone(&shared), changed: changed_rx };
                    if queued && target == ReadbackKind::Launchd { shared.block_pool(&handle); }
                    let mut operation = Box::pin(apply_http_release(fixture.runtime.as_ref().unwrap(), &release, false));
                    let deadline = std::time::Instant::now() + Duration::from_secs(10);
                    let expected = if queued { ReadbackEvent::Queued } else { ReadbackEvent::Entered };
                    loop {
                        assert!(std::time::Instant::now() < deadline, "actual readback boundary did not arrive");
                        tokio::select! { biased;
                            event = events.recv() => {
                                if event == Some((target, expected)) { break; }
                            }
                            (_, result) = operation.as_mut() => panic!("HTTP ended before readback boundary: {result:?}"),
                            _ = tokio::task::yield_now() => {}
                        }
                    }
                    let was_queued = !shared.target_entered.load(Ordering::SeqCst);
                    let before = bytes(fixture.root.path());
                    drop(operation);
                    drop(fixture.runtime.take());
                    let retained = Arc::clone(&fixture.wait_lock).try_lock_owned().is_err();
                    let drained = drain.release_and_drain();
                    let reacquired = Arc::clone(&fixture.wait_lock).try_lock_owned().is_ok();
                    let after = bytes(fixture.root.path());
                    let attempts = fixture.attempts.load(Ordering::SeqCst);
                    let entered_after_release = shared.target_entered.load(Ordering::SeqCst);
                    let expired = shared.expired.load(Ordering::SeqCst);
                    drop(drain);
                    drop(hook);
                    assert!(drained, "actual readback worker did not drain");
                    assert!(!expired, "fixture watchdog released the worker");
                    if queued { assert!(was_queued, "target was not queued when cancelled"); }
                    assert!(entered_after_release, "actual queued closure never ran");
                    assert!(retained, "cancelled HTTP freed its slot while actual readback remained outstanding");
                    assert!(reacquired, "actual worker exit did not release HTTP capacity");
                    assert_eq!(attempts, 0);
                    assert_eq!(after, before, "cancelled readback advanced durable records or target bytes");
                });
            }

            #[test]
            fn http_readback_running_initial_launchd_retains_slot_until_actual_exit() {
                cancellation_case(ReadbackKind::Launchd, false, 1);
            }
            #[test]
            fn http_readback_running_final_launchd_retains_slot_until_actual_exit() {
                cancellation_case(ReadbackKind::Launchd, false, 2);
            }
            #[test]
            fn http_readback_running_staging_identity_retains_slot_until_actual_exit() {
                cancellation_case(ReadbackKind::SystemdIdentity, false, 1);
            }
            #[test]
            fn http_readback_running_final_systemd_retains_slot_until_actual_exit() {
                cancellation_case(ReadbackKind::SystemdPolicy, false, 1);
            }
            #[test]
            fn http_readback_queued_initial_launchd_retains_slot_until_actual_exit() {
                cancellation_case(ReadbackKind::Launchd, true, 1);
            }
            #[test]
            fn http_readback_queued_final_systemd_retains_slot_until_actual_exit() {
                cancellation_case(ReadbackKind::SystemdPolicy, true, 1);
            }

            fn seed_retry(install: &std::path::Path, release: &VerifiedRelease) {
                use crate::upgrade::probe;
                let state = probe::ProbeState {
                    schema_version: 1, record_kind: "probe".into(), install: install.to_owned(),
                    version: release.manifest.version.clone(), platform: release.manifest.assets[0].target.clone(),
                    archive_sha256: release.manifest.assets[0].archive_sha256,
                    transaction_id: "15151515-1515-4515-8515-151515151515".into(), attempt: 1,
                    phase: probe::ProbePhase::InterruptedWait, cause: Some(probe::ProbeCause::Timeout),
                    last_pid: None, boot_id: "http-retry-previous-boot".into(),
                    retry_remaining_ms: 1_800_000, retry_deadline_ms: 1_800_001,
                    daemon_sha256: None, cli_sha256: None,
                };
                assert_ne!(state.boot_id, probe::ProbeClock::now().unwrap().boot_id);
                std::fs::write(probe::state_path(install).unwrap(), serde_json::to_vec(&state).unwrap()).unwrap();
                assert_eq!(probe::read_state(install).unwrap().unwrap().phase, probe::ProbePhase::InterruptedWait);
            }

            fn retry_readback_hook(install: PathBuf, shared: &Arc<Shared>, pause: bool)
                -> (readback_custody_seam::Guard, async_mpsc::UnboundedReceiver<()>) {
                let shared = Arc::clone(shared);
                let (entered, receive) = async_mpsc::unbounded_channel();
                let hook = readback_custody_seam::install(install, Arc::new(move |kind, event| {
                    match event {
                        ReadbackEvent::Queued => { shared.queued.fetch_add(1, Ordering::SeqCst); }
                        ReadbackEvent::Exited => {
                            shared.exited.fetch_add(1, Ordering::SeqCst);
                            let _ = shared.changed.send(());
                        }
                        ReadbackEvent::Entered if kind == ReadbackKind::SystemdIdentity => {
                            shared.target_entered.store(true, Ordering::SeqCst);
                            let _ = entered.send(());
                            if pause { shared.pause(); }
                        }
                        ReadbackEvent::Entered => {}
                    }
                }));
                (hook, receive)
            }

            #[tokio::test]
            async fn http_readback_direct_retry_identity_retains_supplied_slot_until_exit() {
                use crate::upgrade::{apply, probe, staging, staging_selection};
                let mut fixture = Fixture::new();
                let release = Fixture::release();
                let runtime = fixture.runtime.as_ref().unwrap();
                let request = http_staging_request(runtime, &release).unwrap();
                {
                    let _held = crate::upgrade::acquire_host_upgrade_lock(&fixture.install).unwrap();
                    assert_eq!(staging_selection::observe_selected(&request, &probe::ProbeClock::now().unwrap()).unwrap(),
                        staging::Decision::Due);
                    seed_retry(&fixture.install, &release);
                }
                // This checks the actual retry method with a supplied HTTP
                // lease, not the route's post-response slot lifetime.
                let permit = apply::ReleasePermit::for_http(Arc::clone(&runtime.wait_slot));
                let custody = HttpRequestCustody { permit: permit.clone(), completed_attempt: false };
                let upgrader = AutoApplyUpgrader::new("x0xd")
                    .with_stop_on_upgrade(runtime.config.stop_on_upgrade)
                    .with_restart_context(runtime.restart_context.clone())
                    .with_staging_request(request).with_release_permit(permit);
                let (shared, changed) = Shared::new();
                let (hook, mut entered) = retry_readback_hook(fixture.install.clone(), &shared, true);
                let drain = Drain { shared: Arc::clone(&shared), changed };
                let before = bytes(fixture.root.path());
                let mut operation = Box::pin(upgrader.probe_retry_delay(&release.manifest.version));
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                loop {
                    assert!(std::time::Instant::now() < deadline, "actual retry identity did not enter");
                    tokio::select! { biased;
                        event = entered.recv() => { event.unwrap(); break; }
                        result = operation.as_mut() => panic!("retry ended before readback: {result:?}"),
                        _ = tokio::task::yield_now() => {}
                    }
                }
                drop(operation);
                drop(custody); // Real request guard cancels and releases its copy.
                drop(upgrader);
                drop(fixture.runtime.take());
                let retained = Arc::clone(&fixture.wait_lock).try_lock_owned().is_err();
                let drained = drain.release_and_drain();
                let reacquired = Arc::clone(&fixture.wait_lock).try_lock_owned().is_ok();
                let after = bytes(fixture.root.path());
                drop(drain);
                drop(hook);
                assert!(drained && !shared.expired.load(Ordering::SeqCst));
                assert!(shared.target_entered.load(Ordering::SeqCst));
                assert!(retained, "new retry identity call dropped the supplied HTTP lease");
                assert!(reacquired);
                assert_eq!(after, before, "cancelled retry readback must not acknowledge probe progress");
                assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
            }

            async fn returned_retry_case(staging_refusal: bool) {
                use crate::upgrade::{apply, probe, probe_retry, staging_selection};
                struct StopRetry(watch::Sender<bool>);
                impl Drop for StopRetry {
                    fn drop(&mut self) { let _ = self.0.send(true); }
                }
                let mut fixture = Fixture::new();
                let release = Fixture::release();
                let request = http_staging_request(fixture.runtime.as_ref().unwrap(), &release).unwrap();
                let cut = if staging_refusal {
                    std::fs::write(staging_selection::selection_path(&request).unwrap(), b"unknown retained selection").unwrap();
                    None
                } else {
                    let observed = release.clone();
                    Some(apply::pre_probe_admission_seam::install(fixture.install.clone(), Box::new(move |install| {
                        let held = std::fs::OpenOptions::new().read(true).write(true)
                            .open(install.with_file_name("x0xd.upgrade.lock")).unwrap();
                        held.try_lock().unwrap();
                        seed_retry(install, &observed);
                    })))
                };
                // Execute the real helper, then the same retry scheduler the
                // route calls on its returned error. No copied retry flow.
                let (upgrader, result) = tokio::time::timeout(Duration::from_secs(10),
                    apply_http_release(fixture.runtime.as_ref().unwrap(), &release, false)).await.unwrap();
                drop(cut);
                let error = result.unwrap_err().to_string();
                let before = bytes(fixture.root.path());
                let runtime = fixture.runtime.take().unwrap();
                let apply_lock = Arc::clone(&runtime.apply_lock);
                let shutdown = runtime.shutdown.clone();
                drop(runtime); // The real handler's final request-slot owner.
                let free_after_response = Arc::clone(&fixture.wait_lock).try_lock_owned().is_ok();
                let (shared, changed) = Shared::new();
                let (hook, mut entered) = retry_readback_hook(fixture.install.clone(), &shared, !staging_refusal);
                let drain = Drain { shared: Arc::clone(&shared), changed };
                // On unwind, withdraw the scheduled retry before releasing its
                // actual readback worker or removing any scoped input hook.
                let _stop_retry = StopRetry(fixture._shutdown.clone());
                schedule_probe_retry(&upgrader, &release.manifest, apply_lock, shutdown);
                let claim = probe_retry::claim_retry(fixture.install.clone(), release.manifest.version.clone());
                let scheduled = claim.is_none();
                drop(claim);
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut retry_owned_while_paused = false;
                let mut free_during_retry = false;
                if !staging_refusal {
                    loop {
                        assert!(std::time::Instant::now() < deadline, "returned retry identity did not enter");
                        tokio::select! { biased;
                            event = entered.recv() => { event.unwrap(); break; }
                            _ = tokio::task::yield_now() => {}
                        }
                    }
                    let claim = probe_retry::claim_retry(fixture.install.clone(), release.manifest.version.clone());
                    retry_owned_while_paused = claim.is_none();
                    drop(claim);
                    free_during_retry = Arc::clone(&fixture.wait_lock).try_lock_owned().is_ok();
                    fixture._shutdown.send(true).unwrap();
                }
                // The scheduler owns a separate RetryOwner. Shutdown drops its
                // pending check; the actual captured closure still must drain.
                loop {
                    if let Some(owner) = probe_retry::claim_retry(fixture.install.clone(), release.manifest.version.clone()) {
                        drop(owner); break;
                    }
                    assert!(std::time::Instant::now() < deadline, "returned retry owner did not finish");
                    tokio::task::yield_now().await;
                }
                let drained = drain.release_and_drain();
                let after = bytes(fixture.root.path());
                let readbacks = shared.queued.load(Ordering::SeqCst);
                drop(drain);
                drop(hook);
                drop(upgrader);
                assert!(scheduled && free_after_response);
                assert!(drained && !shared.expired.load(Ordering::SeqCst));
                assert_eq!(after, before, "returned/cancelled retry must preserve retained records");
                assert_eq!(fixture.attempts.load(Ordering::SeqCst), 0);
                if staging_refusal {
                    assert_eq!(readbacks, 0, "cancelled setup/staging permit must stop retry before readback");
                } else {
                    assert!(error.contains("probe retry waits"));
                    assert!(retry_owned_while_paused && free_during_retry);
                    assert!(readbacks >= 2, "actual retry must observe launchd and systemd identity");
                    assert_eq!(probe::read_state(&fixture.install).unwrap().unwrap().boot_id,
                        probe::ProbeClock::now().unwrap().boot_id);
                }
            }

            #[tokio::test]
            async fn http_readback_returned_waiting_retry_owns_no_response_slot() {
                returned_retry_case(false).await;
            }

            #[tokio::test]
            async fn http_readback_returned_staging_refusal_stops_retry_before_readback() {
                returned_retry_case(true).await;
            }

            #[tokio::test]
            async fn http_readback_uncancelled_helper_still_applies_once() {
                let mut fixture = Fixture::new();
                let release = Fixture::release();
                let (shared, changed) = Shared::new();
                let observed = Arc::clone(&shared);
                let hook = readback_custody_seam::install(fixture.install.clone(), Arc::new(move |_, event| {
                    match event {
                        ReadbackEvent::Queued => { observed.queued.fetch_add(1, Ordering::SeqCst); }
                        ReadbackEvent::Exited => {
                            observed.exited.fetch_add(1, Ordering::SeqCst);
                            let _ = observed.changed.send(());
                        }
                        ReadbackEvent::Entered => {}
                    }
                }));
                let drain = Drain { shared, changed };
                let outcome = tokio::time::timeout(Duration::from_secs(10),
                    apply_http_release(fixture.runtime.as_ref().unwrap(), &release, false)).await;
                let success = matches!(&outcome, Ok((_, Ok(x0x::upgrade::UpgradeResult::Success { .. }))));
                drop(outcome);
                drop(fixture.runtime.take());
                let drained = drain.release_and_drain();
                drop(drain);
                drop(hook);
                assert!(drained, "actual readback worker did not drain");
                assert!(success);
                assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
                assert!(Arc::clone(&fixture.wait_lock).try_lock_owned().is_ok());
            }
        }
    };
}
