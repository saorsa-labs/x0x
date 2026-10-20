// Expanded inside server::routes::upgrade::tests. The standalone integration
// target is inert. These test the production helper, not discovery-loop drain,
// signature verification, or eventual ownership of a background wait.
#[allow(unused_macros)]
macro_rules! background_staging_regression_tests {
    () => {
        #[cfg(unix)]
        mod background_staging_regressions {
            use super::*;
            use std::io::Read;
            use std::path::{Path, PathBuf};
            use std::process::{Child, Command, Stdio};
            use std::time::Instant;

            const ROOT: &str = "X0X_BACKGROUND_STAGING_FIXTURE_ROOT";
            const WINDOW: &str = "X0X_BACKGROUND_STAGING_FIXTURE_WINDOW";
            const CHILD: &str = concat!(
                "server::routes::upgrade::tests::background_staging_regressions::",
                "background_staging_owned_fixture"
            );

            struct OwnedChild(Child);

            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }

            fn digest(path: &Path) -> [u8; 32] {
                use sha2::Digest;
                let mut file = std::fs::File::open(path).unwrap();
                let mut hash = sha2::Sha256::new();
                let mut bytes = [0_u8; 64 * 1024];
                loop {
                    let count = file.read(&mut bytes).unwrap();
                    if count == 0 {
                        return hash.finalize().into();
                    }
                    hash.update(&bytes[..count]);
                }
            }

            fn owned_background_observation(window: u64) -> serde_json::Value {
                let evidence = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning/upgrade-staging-fixtures"));
                std::fs::create_dir_all(&evidence).unwrap();
                let dir = tempfile::Builder::new().prefix("background-")
                    .tempdir_in(evidence).unwrap();
                let root = dir.path().canonicalize().unwrap();
                for name in ["install", "data", "home", "tmp", "profiles"] {
                    std::fs::create_dir(root.join(name)).unwrap();
                }
                let executable = root.join("install/x0xd");
                // Copy, never hard-link: the real preflight checks probe state
                // and takes its persistent install lock beside this executable.
                std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
                let original = digest(&executable);
                std::fs::write(root.join("data/sentinel"), b"configured state").unwrap();
                let log = std::fs::File::create(root.join("child.log")).unwrap();
                let mut child = OwnedChild(Command::new(&executable)
                    .args(["--exact", CHILD, "--ignored", "--nocapture"])
                    .env_clear()
                    .env(ROOT, &root).env(WINDOW, window.to_string())
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", root.join("home"))
                    .env("XDG_CONFIG_HOME", root.join("home/config"))
                    .env("XDG_DATA_HOME", root.join("home/data"))
                    .env("XDG_CACHE_HOME", root.join("home/cache"))
                    .env("TMPDIR", root.join("tmp"))
                    .env("TMP", root.join("tmp"))
                    .env("TEMP", root.join("tmp"))
                    .env("LLVM_PROFILE_FILE", root.join("profiles/fixture-%p-%m.profraw"))
                    .current_dir(&root).stdin(Stdio::null())
                    .stdout(Stdio::from(log.try_clone().unwrap()))
                    .stderr(Stdio::from(log)).spawn().unwrap());
                let deadline = Instant::now() + Duration::from_secs(20);
                let status = loop {
                    if let Some(status) = child.0.try_wait().unwrap() {
                        break status;
                    }
                    assert!(Instant::now() < deadline,
                        "owned inert child exceeded its bound; log: {}", root.join("child.log").display());
                    std::thread::sleep(Duration::from_millis(10));
                };
                assert!(status.success(), "owned inert child failed; log: {}",
                    root.join("child.log").display());
                let report: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(root.join("result.json")).unwrap()).unwrap();
                assert_eq!(report["configured_window_minutes"], window);
                assert_eq!(report["virtual_elapsed_ms"], 1000);
                assert_eq!(report["shutdown_calls"], 0);
                assert_eq!(digest(&executable), original);
                assert_eq!(std::fs::read(root.join("data/sentinel")).unwrap(), b"configured state");
                assert!(!root.join("install/x0xd.backup").exists());
                assert!(!root.join("data/upgrade-handoff.json").exists());
                report
            }

            #[test]
            fn background_staging_positive_window_defers_destructive_admission() {
                let report = owned_background_observation(60);
                assert_eq!(report["attempts"], 0,
                    "the real background helper must honor its nonzero staging window \
                     before destructive admission: {report}");
            }

            #[test]
            fn background_staging_zero_window_reaches_the_real_apply_hook_once() {
                let report = owned_background_observation(0);
                assert_eq!(report["attempts"], 1, "{report}");
                assert_eq!(report["success"], true, "{report}");
                assert_eq!(report["applied_version"], "9.9.9", "{report}");
            }

            #[tokio::test(start_paused = true)]
            #[ignore = "owned copied-libtest child only; never a daemon"]
            async fn background_staging_owned_fixture() {
                let Some(root) = std::env::var_os(ROOT).map(PathBuf::from) else { return; };
                let window: u64 = std::env::var(WINDOW).unwrap().parse().unwrap();
                let install = std::env::current_exe().unwrap().canonicalize().unwrap();
                assert_eq!(install, root.join("install/x0xd"));
                let data = root.join("data");
                let config = DaemonUpdateConfig { rollout_window_minutes: window, ..Default::default() };
                let mut scenario = one_call_scenario("0", "5");
                // An ordinary untracked unit isolates configured staging from
                // the separate production fleet-minimum policy.
                scenario.cgroup = "0::/system.slice/x0x-background-test.service".into();
                let _readback = restart::systemd_readback_seam::install(scenario);
                let attempts = Arc::new(AtomicU64::new(0));
                let counted = Arc::clone(&attempts);
                let expected_install = install.clone();
                let expected_data = data.clone();
                let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |plan, manifest| {
                    assert_eq!(plan.executable, expected_install);
                    assert_eq!(plan.data_root, expected_data);
                    counted.fetch_add(1, Ordering::SeqCst);
                    // Observe admission. Do not change VERSION, installed
                    // bytes, reported process identity, or restart anything.
                    x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
                }));
                let shutdown_calls = Arc::new(AtomicU64::new(0));
                let counted_shutdown = Arc::clone(&shutdown_calls);
                let shutdown: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                    counted_shutdown.fetch_add(1, Ordering::SeqCst);
                });
                let mut manifest = manifest_for_this_platform("9.9.9");
                manifest.timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                manifest.assets[0].archive_url = "background-fixture://no-download".into();
                manifest.assets[0].signature_url = "background-fixture://no-download".into();
                let started = tokio::time::Instant::now();
                let (_shutdown_tx, shutdown_watch) = watch::channel(false);
                let runtime = BackgroundRuntime {
                    config, data_dir: data.clone(),
                    api_addr: SocketAddr::from(([127, 0, 0, 1], 12700)),
                    shutdown: (shutdown, shutdown_watch),
                    apply_lock: Arc::new(Mutex::new(())),
                    staging: StartupStagingContext {
                        install: install.clone(), identity_root: data.clone(), machine_id: [42; 32],
                        observed: None,
                        clock: Some(Arc::new(move || Ok(crate::upgrade::probe::ProbeClock {
                            boot_id: "background-owned-fixture".into(),
                            monotonic_ms: 1000 + u64::try_from(started.elapsed().as_millis())
                                .map_err(std::io::Error::other)?,
                        }))),
                    },
                    operation_observer: None,
                };
                let verified = crate::upgrade::monitor::VerifiedRelease {
                    manifest_json: serde_json::to_vec(&manifest).unwrap(), manifest,
                    signature: Vec::new(), gossip_payload: Vec::new(),
                };
                let permit = crate::upgrade::apply::ReleasePermit::default();
                let mut result = None;
                {
                    // This is the helper called by BOTH real background loops.
                    // GREEN supplies the same real boot identity and original
                    // manifest bytes now carried by production. The prior RED
                    // commit used this helper before it accepted these inputs.
                    let operation = apply_background_release(&runtime, &verified, &permit);
                    tokio::pin!(operation);
                    for step in 0..2 {
                        if step == 1 {
                            tokio::time::advance(Duration::from_secs(1)).await;
                        }
                        let wall_deadline = Instant::now() + Duration::from_secs(2);
                        while result.is_none() && Instant::now() < wall_deadline {
                            tokio::select! {
                                biased;
                                (_, observed) = &mut operation => { result = Some(observed); }
                                _ = tokio::task::yield_now() => {}
                            }
                        }
                    }
                    // Drop pending pre-admission work before the scoped hook
                    // guards. The parent also bounds and reaps the whole child.
                }
                let success = matches!(&result,
                    Some(Ok(x0x::upgrade::UpgradeResult::Success { version })) if version == "9.9.9");
                let report = serde_json::json!({
                    "configured_window_minutes": window,
                    "virtual_elapsed_ms": started.elapsed().as_millis(),
                    "attempts": attempts.load(Ordering::SeqCst),
                    "success": success,
                    "applied_version": if success { "9.9.9" } else { "" },
                    "shutdown_calls": shutdown_calls.load(Ordering::SeqCst),
                    "result": format!("{result:?}"),
                });
                std::fs::write(root.join("result.json"), serde_json::to_vec(&report).unwrap()).unwrap();
            }
        }
    };
}

// Separately expanded inside upgrade::apply::tests. These exercise the actual
// replacement worker with the release permit, not a synthetic mutation closure.
#[allow(unused_macros)]
macro_rules! background_permit_regression_tests {
    () => {
        #[cfg(unix)]
        mod background_permit_regressions {
            use super::*;
            use std::time::Duration;

            struct ReleasePause(Option<std::sync::mpsc::Sender<()>>);
            impl Drop for ReleasePause {
                fn drop(&mut self) {
                    if let Some(release) = self.0.take() { let _ = release.send(()); }
                }
            }

            #[tokio::test]
            async fn background_release_cancel_before_admission_preserves_pair() {
                release_cancellation_case(false).await;
            }

            #[tokio::test]
            async fn background_release_cancel_after_admission_retains_pair_and_continuation() {
                release_cancellation_case(true).await;
            }

            async fn release_cancellation_case(after_admission: bool) {
                let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning/upgrade-staging-fixtures"));
                std::fs::create_dir_all(&base).unwrap();
                let root = tempfile::Builder::new().prefix("release-permit-").tempdir_in(base).unwrap();
                let scratch = root.path().join("scratch");
                std::fs::create_dir(&scratch).unwrap();
                let daemon = root.path().join("x0xd");
                let cli = root.path().join("x0x");
                std::fs::write(&daemon, b"old-daemon").unwrap();
                std::fs::write(&cli, b"old-cli").unwrap();
                let incoming = scratch.join("daemon");
                let incoming_cli = scratch.join("cli");
                std::fs::write(&incoming, b"new-daemon").unwrap();
                std::fs::write(&incoming_cli, b"new-cli").unwrap();
                let marker = root.path().join("actual-continuation");
                let continued = marker.clone();
                let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
                let permit = ReleasePermit {
                    observer: Some(Arc::new(move |entered| { let _ = events_tx.send(entered); })),
                    ..Default::default()
                };
                let mut held = if after_admission { None } else {
                    Some(crate::upgrade::acquire_host_upgrade_lock(&daemon).unwrap())
                };
                let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
                let (release_tx, release_rx) = std::sync::mpsc::channel();
                let pause = if after_admission {
                    REPLACE_HOOK_INIT.call_once(|| {
                        tracing::subscriber::set_global_default(PauseAtReplacingBinary).unwrap();
                    });
                    REPLACE_HOOKS.lock().unwrap().insert(daemon.clone(), ReplaceHook {
                        entered: entered_tx, release: release_rx,
                    });
                    Some(ReplaceHookGuard { target: daemon.clone() })
                } else { None };
                let release = ReleasePause(Some(release_tx));
                let operation = apply_replacements_with_permit(
                    Upgrader::new(daemon.clone(), semver::Version::new(1, 0, 0)), incoming,
                    semver::Version::new(2, 0, 0),
                    Some((Upgrader::new(cli.clone(), semver::Version::new(1, 0, 0)), incoming_cli)),
                    TempDirGuard { path: scratch.clone() },
                    Some(Box::new(move || std::fs::write(continued, b"restart owned").unwrap())),
                    None, Some(&permit),
                );
                tokio::pin!(operation);
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::select! {
                        result = operation.as_mut() => panic!("replacement ended before its actual worker entered: {result:?}"),
                        event = events_rx.recv() => assert_eq!(event, Some(true)),
                    }
                }).await.unwrap();
                if after_admission {
                    tokio::time::timeout(Duration::from_secs(5), async {
                        tokio::select! {
                            result = operation.as_mut() => panic!("replacement ended before the between-renames pause: {result:?}"),
                            entered = entered_rx => entered.unwrap(),
                        }
                    }).await.unwrap();
                    // The actual CLI rename proves admission already occurred.
                    assert_eq!(std::fs::read(&cli).unwrap(), b"new-cli");
                    assert_eq!(std::fs::read(cli.with_extension("backup")).unwrap(), b"old-cli");
                    assert_eq!(std::fs::read(daemon.with_extension("backup")).unwrap(), b"old-daemon");
                } else {
                    assert_eq!(std::fs::read(&cli).unwrap(), b"old-cli");
                    assert!(!cli.with_extension("backup").exists());
                    assert!(!daemon.with_extension("backup").exists());
                }
                assert_eq!(std::fs::read(&daemon).unwrap(), b"old-daemon");
                assert!(!marker.exists());
                permit.cancel();
                drop(held.take());
                drop(release);
                let result = tokio::time::timeout(Duration::from_secs(5), operation.as_mut()).await.unwrap();
                assert_eq!(tokio::time::timeout(Duration::from_secs(5), events_rx.recv()).await.unwrap(),
                    Some(false), "actual worker must exit");
                assert!(events_rx.try_recv().is_err());
                assert!(!scratch.exists());
                if after_admission {
                    assert!(matches!(result, Ok(UpgradeResult::Success { .. })), "{result:?}");
                    assert_eq!(std::fs::read(&daemon).unwrap(), b"new-daemon");
                    assert_eq!(std::fs::read(&cli).unwrap(), b"new-cli");
                    assert_eq!(std::fs::read(&marker).unwrap(), b"restart owned");
                    assert_eq!(std::fs::read(daemon.with_extension("backup")).unwrap(), b"old-daemon");
                    assert_eq!(std::fs::read(cli.with_extension("backup")).unwrap(), b"old-cli");
                } else {
                    assert!(result.is_err(), "{result:?}");
                    assert_eq!(std::fs::read(&daemon).unwrap(), b"old-daemon");
                    assert_eq!(std::fs::read(&cli).unwrap(), b"old-cli");
                    assert!(!marker.exists());
                    assert!(!daemon.with_extension("backup").exists());
                    assert!(!cli.with_extension("backup").exists());
                }
                assert!(permit.check().is_err());
                drop(pause);
            }
        }
    };
}

// Production-used ingress drivers and owner. Fixtures replace only verified
// discovery input and publication I/O; receipts, admission and custody are real.
#[allow(unused_macros)]
macro_rules! background_driver_regression_tests {
    () => {
        #[cfg(unix)]
        mod background_driver_regressions {
            use super::*;
            use sha2::Digest;
            use std::collections::{BTreeMap, VecDeque};
            use std::future::Future;
            use std::pin::Pin;
            use std::sync::Mutex as StdMutex;
            use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

            type Driver = Pin<Box<dyn Future<Output = ()>>>;
            struct Fixture {
                submit: BackgroundSubmit,
                owner: Option<BackgroundOwner>,
                shutdown: Option<watch::Sender<bool>>,
                shutdown_watch: watch::Receiver<bool>,
                processed: UnboundedReceiver<(String, SubmitOutcome)>,
                observed: UnboundedReceiver<crate::upgrade::staging::Decision>,
                operations: UnboundedReceiver<bool>,
                applied: UnboundedReceiver<String>,
                attempts: Arc<StdMutex<Vec<String>>>,
                apply_lock: Arc<Mutex<()>>,
                install: PathBuf,
                data: PathBuf,
                identity: PathBuf,
                window: u64,
                timestamp: u64,
                _readback: restart::systemd_readback_seam::Guard,
                _apply: crate::upgrade::apply::apply_attempt_seam::Guard,
                _root: tempfile::TempDir,
            }

            impl Fixture {
                fn new(window: u64) -> Self {
                    let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                        .map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join(".planning/upgrade-staging-fixtures"));
                    std::fs::create_dir_all(&base).unwrap();
                    let root = tempfile::Builder::new().prefix("background-driver-").tempdir_in(base).unwrap();
                    let data = root.path().join("data");
                    let identity = root.path().join("identity");
                    std::fs::create_dir(&data).unwrap();
                    std::fs::create_dir(&identity).unwrap();
                    let data = data.canonicalize().unwrap();
                    let identity = identity.canonicalize().unwrap();
                    let (mut startup, shutdown) = e2e_startup_runtime(&data);
                    startup.staging.identity_root = identity.clone();
                    let install = startup.staging.install.clone();
                    std::fs::write(data.join("SKILL.md"), b"original guide").unwrap();
                    let (observed_tx, observed) = mpsc::unbounded_channel();
                    startup.staging.observed = Some(Arc::new(move |decision| {
                        let _ = observed_tx.send(decision);
                    }));
                    let readback = restart::systemd_readback_seam::install(staging_readback(
                        one_call_scenario("0", "5"), &startup,
                    ));
                    let (operation_tx, operations) = mpsc::unbounded_channel();
                    let (applied_tx, applied) = mpsc::unbounded_channel();
                    let attempts = Arc::new(StdMutex::new(Vec::new()));
                    let counted = Arc::clone(&attempts);
                    let expected_install = install.clone();
                    let expected_data = data.clone();
                    let apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(move |plan, manifest| {
                        assert_eq!(plan.executable, expected_install);
                        assert_eq!(plan.data_root, expected_data);
                        counted.lock().unwrap().push(manifest.version.clone());
                        let _ = applied_tx.send(manifest.version.clone());
                        x0x::upgrade::UpgradeResult::Success { version: manifest.version.clone() }
                    }));
                    let apply_lock = Arc::clone(&startup.upgrade_apply_lock);
                    let shutdown_watch = startup.shutdown_watch.clone();
                    let (mut submit, owner) = background_channel(BackgroundRuntime {
                        config: DaemonUpdateConfig { rollout_window_minutes: window, ..Default::default() },
                        data_dir: data.clone(), api_addr: SocketAddr::from(([127, 0, 0, 1], 12700)),
                        shutdown: (Arc::new(|| panic!("fixture must never restart")), startup.shutdown_watch),
                        apply_lock: Arc::clone(&apply_lock), staging: startup.staging,
                        operation_observer: Some(Arc::new(move |entered| { let _ = operation_tx.send(entered); })),
                    });
                    let (processed_tx, processed) = mpsc::unbounded_channel();
                    submit.processed = Some(Arc::new(move |version, outcome| {
                        let _ = processed_tx.send((version, outcome));
                    }));
                    Self { submit, owner: Some(owner), shutdown: Some(shutdown), shutdown_watch,
                        processed, observed, operations, applied, attempts, apply_lock,
                        install, data, identity, window,
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                        _readback: readback, _apply: apply, _root: root }
                }

                fn release(&self, version: &str) -> crate::upgrade::monitor::VerifiedRelease {
                    let mut manifest = manifest_for_this_platform(version);
                    manifest.timestamp = self.timestamp;
                    manifest.skill_sha256 = sha2::Sha256::digest(b"original guide").into();
                    let bytes = serde_json::to_vec(&manifest).unwrap();
                    crate::upgrade::monitor::VerifiedRelease {
                        manifest, manifest_json: bytes.clone(), signature: Vec::new(), gossip_payload: bytes,
                    }
                }

                fn request(&self, release: &crate::upgrade::monitor::VerifiedRelease) -> crate::upgrade::staging::StagingRequest {
                    crate::upgrade::staging::StagingRequest {
                        install: self.install.clone(), data_root: self.data.clone(), identity_root: self.identity.clone(),
                        machine_id: [42; 32], version: release.manifest.version.clone(),
                        manifest_sha256: sha2::Sha256::digest(&release.manifest_json).into(),
                        archive_sha256: release.manifest.assets[0].archive_sha256, window_minutes: self.window,
                    }
                }

                fn gossip(&self) -> (UnboundedSender<crate::upgrade::monitor::VerifiedRelease>, Driver) {
                    let (send, receive) = mpsc::unbounded_channel();
                    let releases = futures::stream::unfold(receive, |mut receive| async {
                        receive.recv().await.map(|value| (value, receive))
                    });
                    let future = run_gossip_update_driver(releases, self.submit.clone(),
                        Arc::new(Mutex::new(SelfPublishedReleaseManifests::default())),
                        |_| async { Ok(()) }, self.shutdown_watch.clone());
                    (send, Box::pin(future))
                }

                fn fallback(&self, queued: Arc<StdMutex<VecDeque<crate::upgrade::monitor::VerifiedRelease>>>,
                    checks: Arc<AtomicU64>) -> Driver {
                    let submit = self.submit.clone();
                    let shutdown = self.shutdown_watch.clone();
                    Box::pin(async move {
                        let mut ticker = tokio::time::interval(Duration::from_secs(60));
                        ticker.tick().await;
                        let ticks = futures::stream::unfold(ticker, |mut ticker| async {
                            ticker.tick().await; Some(((), ticker))
                        });
                        run_fallback_update_driver(ticks, move || {
                            checks.fetch_add(1, Ordering::SeqCst);
                            let release = queued.lock().unwrap().pop_front();
                            async move { Ok(release) }
                        }, submit, Arc::new(Mutex::new(SelfPublishedReleaseManifests::default())),
                            |_| async { Ok(()) }, shutdown).await;
                    })
                }

                fn bytes(&self) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
                    std::fs::read_dir(&self.data).unwrap().map(|entry| entry.unwrap())
                        .filter(|entry| entry.file_type().unwrap().is_file())
                        .map(|entry| (entry.file_name(), std::fs::read(entry.path()).unwrap())).collect()
                }

                fn stop(&mut self) { self.shutdown.as_ref().unwrap().send(true).unwrap(); }
            }

            async fn event<F: Future<Output = ()>, T>(mut running: Pin<&mut F>,
                events: &mut UnboundedReceiver<T>) -> T {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                loop {
                    assert!(std::time::Instant::now() < deadline, "actual background event deadline");
                    tokio::select! {
                        biased;
                        result = running.as_mut() => panic!("background owner/drivers ended before event: {result:?}"),
                        event = events.recv() => return event.expect("actual event producer remains alive"),
                        _ = tokio::task::yield_now() => {}
                    }
                }
            }

            async fn finish<F: Future<Output = ()>>(mut running: Pin<&mut F>) {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                loop {
                    assert!(std::time::Instant::now() < deadline, "actual background completion deadline");
                    tokio::select! {
                        biased;
                        _ = running.as_mut() => return,
                        _ = tokio::task::yield_now() => {}
                    }
                }
            }

            #[tokio::test(start_paused = true)]
            async fn background_gossip_drains_duplicates_and_supersedes_before_due_once() {
                let mut fixture = Fixture::new(60);
                let mut older = fixture.release("9.9.9");
                older.manifest.skill_url = "inert-guide://must-not-download-before-due".into();
                older.manifest.skill_sha256 = sha2::Sha256::digest(b"candidate guide").into();
                older.manifest_json = serde_json::to_vec(&older.manifest).unwrap();
                older.gossip_payload = older.manifest_json.clone();
                let older_request = fixture.request(&older);
                let newer = fixture.release("9.9.10");
                let newer_request = fixture.request(&newer);
                let older_json = older.manifest_json.clone();
                let (download_tx, mut download_rx) = tokio::sync::oneshot::channel();
                let _guide = skill_download_seam::install(async move {
                    let _ = download_tx.send(());
                    std::future::pending::<Vec<u8>>().await
                });
                let (input, driver) = fixture.gossip();
                let owner = fixture.owner.take().unwrap();
                let running = async { tokio::join!(owner.run(), driver); };
                tokio::pin!(running);
                input.send(older).unwrap();
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.9".into(), SubmitOutcome::Accepted));
                assert_eq!(event(running.as_mut(), &mut fixture.observed).await,
                    crate::upgrade::staging::Decision::Waiting(Duration::from_secs(3260)));
                let old_path = crate::upgrade::staging::receipt_path(&older_request).unwrap();
                let old_bytes = std::fs::read(&old_path).unwrap();
                assert!(fixture.apply_lock.try_lock().is_ok());
                assert!(fixture.attempts.lock().unwrap().is_empty());
                assert!(download_rx.try_recv().is_err(), "guide download must wait with the release");
                let duplicate_manifest = serde_json::from_slice(&older_json).unwrap();
                input.send(crate::upgrade::monitor::VerifiedRelease {
                    manifest: duplicate_manifest, manifest_json: older_json.clone(),
                    signature: Vec::new(), gossip_payload: older_json,
                }).unwrap();
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.9".into(), SubmitOutcome::Duplicate));
                assert_eq!(std::fs::read(&old_path).unwrap(), old_bytes);
                assert!(fixture.observed.try_recv().is_err(), "duplicate cannot restart a waiter");
                input.send(newer).unwrap();
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.10".into(), SubmitOutcome::Accepted));
                assert_eq!(event(running.as_mut(), &mut fixture.observed).await,
                    crate::upgrade::staging::Decision::Waiting(Duration::from_secs(1276)));
                assert_eq!(std::fs::read(&old_path).unwrap(), old_bytes);
                assert!(crate::upgrade::staging_selection::check_request(&older_request).is_err());
                let newer_receipt = crate::upgrade::staging::read_receipt(&newer_request).unwrap().unwrap();
                assert_eq!(newer_receipt.first_receipt_ms, 1000);
                assert_eq!(newer_receipt.chosen_delay, Duration::from_secs(1276));
                input.send(fixture.release("9.9.9")).unwrap();
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.9".into(), SubmitOutcome::Older));
                tokio::time::advance(Duration::from_secs(1276)).await;
                assert_eq!(event(running.as_mut(), &mut fixture.applied).await, "9.9.10");
                input.send(fixture.release("9.9.10")).unwrap();
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.10".into(), SubmitOutcome::Duplicate));
                fixture.stop();
                finish(running.as_mut()).await;
                assert_eq!(*fixture.attempts.lock().unwrap(), vec!["9.9.10".to_owned()]);
                assert_eq!(std::fs::read(&fixture.install).unwrap(), b"owned startup staging executable fixture");
                assert_eq!(std::fs::read(fixture.data.join("SKILL.md")).unwrap(), b"original guide");
                assert!(download_rx.try_recv().is_err(), "superseded guide was never downloaded");
                assert_eq!(std::fs::read(old_path).unwrap(), old_bytes);
            }

            #[tokio::test(start_paused = true)]
            async fn background_fallback_keeps_checking_while_first_receipt_waits() {
                let mut fixture = Fixture::new(60);
                let first = fixture.release("9.9.9");
                let request = fixture.request(&first);
                let queued = Arc::new(StdMutex::new(VecDeque::from([
                    first, fixture.release("9.9.9"), fixture.release("9.9.10"),
                ])));
                let checks = Arc::new(AtomicU64::new(0));
                let driver = fixture.fallback(Arc::clone(&queued), Arc::clone(&checks));
                let owner = fixture.owner.take().unwrap();
                let running = async { tokio::join!(owner.run(), driver); };
                tokio::pin!(running);
                // Poll once to establish the real interval before advancing it.
                std::future::poll_fn(|cx| {
                    assert!(running.as_mut().poll(cx).is_pending()); std::task::Poll::Ready(())
                }).await;
                tokio::time::advance(Duration::from_secs(60)).await;
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.9".into(), SubmitOutcome::Accepted));
                assert_eq!(event(running.as_mut(), &mut fixture.observed).await,
                    crate::upgrade::staging::Decision::Waiting(Duration::from_secs(3260)));
                let first = crate::upgrade::staging::read_receipt(&request).unwrap().unwrap();
                assert_eq!(first.first_receipt_ms, 61_000);
                tokio::time::advance(Duration::from_secs(60)).await;
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.9".into(), SubmitOutcome::Duplicate));
                assert_eq!(checks.load(Ordering::SeqCst), 2);
                assert!(fixture.attempts.lock().unwrap().is_empty());
                assert!(fixture.apply_lock.try_lock().is_ok());
                let retained = crate::upgrade::staging::read_receipt(&request).unwrap().unwrap();
                assert_eq!(retained.first_receipt_ms, first.first_receipt_ms);
                assert_eq!(retained.chosen_delay, first.chosen_delay);
                tokio::time::advance(Duration::from_secs(60)).await;
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.10".into(), SubmitOutcome::Accepted));
                assert_eq!(checks.load(Ordering::SeqCst), 3);
                // Wait for the newer real barrier before shutdown, so no
                // detached observation can make a later byte snapshot vacuous.
                loop {
                    let decision = event(running.as_mut(), &mut fixture.observed).await;
                    if decision == crate::upgrade::staging::Decision::Waiting(Duration::from_secs(1276)) { break; }
                    assert!(matches!(decision, crate::upgrade::staging::Decision::Waiting(_)));
                }
                fixture.stop();
                finish(running.as_mut()).await;
                let preserved = fixture.bytes();
                tokio::time::advance(Duration::from_secs(7200)).await;
                assert_eq!(fixture.bytes(), preserved);
                assert!(fixture.attempts.lock().unwrap().is_empty());
                assert_eq!(checks.load(Ordering::SeqCst), 3);
            }

            #[tokio::test(start_paused = true)]
            async fn background_shared_drivers_coalesce_while_cancelled_worker_drains() {
                let mut fixture = Fixture::new(60);
                let held = crate::upgrade::acquire_host_upgrade_lock(&fixture.install).unwrap();
                let original = fixture.bytes();
                let first = fixture.release("9.9.9");
                let mut superseded = vec![fixture.request(&first)];
                let from_poll = fixture.release("9.9.10");
                superseded.push(fixture.request(&from_poll));
                let queued = Arc::new(StdMutex::new(VecDeque::from([from_poll])));
                let checks = Arc::new(AtomicU64::new(0));
                let fallback = fixture.fallback(queued, Arc::clone(&checks));
                let (input, gossip) = fixture.gossip();
                let owner = fixture.owner.take().unwrap();
                let running = async { tokio::join!(owner.run(), gossip, fallback); };
                tokio::pin!(running);
                input.send(first).unwrap();
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.9".into(), SubmitOutcome::Accepted));
                assert!(event(running.as_mut(), &mut fixture.operations).await,
                    "real first blocking operation must enter before lock release");
                assert_eq!(fixture.bytes(), original);
                tokio::time::advance(Duration::from_secs(60)).await;
                assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                    ("9.9.10".into(), SubmitOutcome::Accepted));
                assert_eq!(checks.load(Ordering::SeqCst), 1);
                assert!(fixture.operations.try_recv().is_err(), "poll submission cannot start another queued worker");
                for version in ["9.9.11", "9.9.12", "9.9.99"] {
                    let release = fixture.release(version);
                    if version != "9.9.99" { superseded.push(fixture.request(&release)); }
                    input.send(release).unwrap();
                    assert_eq!(event(running.as_mut(), &mut fixture.processed).await,
                        (version.into(), SubmitOutcome::Accepted));
                    assert!(fixture.operations.try_recv().is_err(),
                        "new discovery must coalesce, not spawn another blocked worker");
                    assert_eq!(fixture.bytes(), original);
                }
                assert!(fixture.apply_lock.try_lock().is_ok());
                assert!(fixture.attempts.lock().unwrap().is_empty());
                drop(held);
                // Callbacks run inside actual blocking closures: the old exit
                // precedes entry of the sole coalesced replacement observation.
                assert!(!event(running.as_mut(), &mut fixture.operations).await);
                assert!(event(running.as_mut(), &mut fixture.operations).await);
                assert!(!event(running.as_mut(), &mut fixture.operations).await);
                assert_eq!(event(running.as_mut(), &mut fixture.observed).await,
                    crate::upgrade::staging::Decision::Waiting(Duration::from_secs(2890)));
                for request in superseded {
                    assert!(!crate::upgrade::staging::receipt_path(&request).unwrap().exists(),
                        "cancelled/coalesced release {} must not acquire a first receipt", request.version);
                }
                let latest = fixture.request(&fixture.release("9.9.99"));
                let receipt = crate::upgrade::staging::read_receipt(&latest).unwrap().unwrap();
                assert_eq!(receipt.first_receipt_ms, 61_000, "queued time is not durable wait");
                assert_eq!(receipt.chosen_delay, Duration::from_secs(2890));
                assert_eq!(crate::upgrade::staging_selection::read_selection(&latest).unwrap().unwrap().release.version,
                    "9.9.99");
                assert!(fixture.operations.try_recv().is_err());
                fixture.stop();
                finish(running.as_mut()).await;
                assert!(fixture.attempts.lock().unwrap().is_empty());
                assert_eq!(std::fs::read(&fixture.install).unwrap(), b"owned startup staging executable fixture");
            }

            #[tokio::test(start_paused = true)]
            async fn background_shutdown_closed_watch_and_drop_refuse_queued_record_writes() {
                for mode in ["signal", "closed", "drop"] {
                    let mut fixture = Fixture::new(60);
                    let held = crate::upgrade::acquire_host_upgrade_lock(&fixture.install).unwrap();
                    let original = fixture.bytes();
                    let (input, driver) = fixture.gossip();
                    let owner = fixture.owner.take().unwrap();
                    let mut running = Some(Box::pin(async { tokio::join!(owner.run(), driver); }));
                    input.send(fixture.release("9.9.9")).unwrap();
                    assert_eq!(event(running.as_mut().unwrap().as_mut(), &mut fixture.processed).await,
                        ("9.9.9".into(), SubmitOutcome::Accepted));
                    assert!(event(running.as_mut().unwrap().as_mut(), &mut fixture.operations).await);
                    match mode {
                        "signal" => fixture.stop(),
                        "closed" => drop(fixture.shutdown.take()),
                        "drop" => drop(running.take()),
                        _ => unreachable!(),
                    }
                    if let Some(running) = running.as_mut() { finish(running.as_mut()).await; }
                    assert_eq!(fixture.bytes(), original);
                    drop(held);
                    // Await the actual abandoned blocking closure's exit. A
                    // cancelled owner return alone does not prove disk custody.
                    let deadline = std::time::Instant::now() + Duration::from_secs(20);
                    loop {
                        assert!(std::time::Instant::now() < deadline, "cancelled worker exit bound");
                        match fixture.operations.try_recv() {
                            Ok(entered) => { assert!(!entered, "shutdown must not start another worker"); break; }
                            Err(mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
                            Err(error) => panic!("worker exit witness lost: {error}"),
                        }
                    }
                    assert_eq!(fixture.bytes(), original, "late record write after {mode}");
                    assert!(fixture.attempts.lock().unwrap().is_empty());
                    assert!(fixture.submit.submit(fixture.release("9.9.10")).is_err());
                    assert!(fixture.operations.try_recv().is_err());
                    assert!(fixture.observed.try_recv().is_err());
                }
            }
        }
    };
}
