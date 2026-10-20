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
