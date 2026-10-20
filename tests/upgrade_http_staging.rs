// Expanded inside server::routes::upgrade::tests. The standalone integration
// target is inert. This covers the production HTTP apply operation, not the
// authenticated router, socket disconnects, or response-flush restart custody.
#[allow(unused_macros)]
macro_rules! http_staging_regression_tests {
    () => {
        #[cfg(unix)]
        mod http_staging_regressions {
            use super::*;
            use std::io::Read;
            use std::path::{Path, PathBuf};
            use std::process::{Child, Command, Stdio};
            use std::time::Instant;

            const ROOT: &str = "X0X_HTTP_STAGING_FIXTURE_ROOT";
            const WINDOW: &str = "X0X_HTTP_STAGING_FIXTURE_WINDOW";
            const CHILD: &str = concat!(
                "server::routes::upgrade::tests::http_staging_regressions::",
                "http_staging_owned_fixture"
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

            fn owned_http_observation(window: u64) -> serde_json::Value {
                let evidence = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning/upgrade-staging-fixtures"));
                std::fs::create_dir_all(&evidence).unwrap();
                let dir = tempfile::Builder::new().prefix("http-")
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
            fn http_staging_positive_window_defers_destructive_admission() {
                let report = owned_http_observation(60);
                assert_eq!(report["attempts"], 0,
                    "the real http helper must honor its nonzero staging window \
                     before destructive admission: {report}");
            }

            #[test]
            fn http_staging_zero_window_reaches_the_real_apply_hook_once() {
                let report = owned_http_observation(0);
                assert_eq!(report["attempts"], 1, "{report}");
                assert_eq!(report["success"], true, "{report}");
                assert_eq!(report["applied_version"], "9.9.9", "{report}");
            }

            #[tokio::test(start_paused = true)]
            #[ignore = "owned copied-libtest child only; never a daemon"]
            async fn http_staging_owned_fixture() {
                let Some(root) = std::env::var_os(ROOT).map(PathBuf::from) else { return; };
                let window: u64 = std::env::var(WINDOW).unwrap().parse().unwrap();
                let install = std::env::current_exe().unwrap().canonicalize().unwrap();
                assert_eq!(install, root.join("install/x0xd"));
                let data = root.join("data");
                let config = DaemonUpdateConfig { rollout_window_minutes: window, ..Default::default() };
                let mut scenario = one_call_scenario("0", "5");
                // An ordinary untracked unit isolates configured staging from
                // the separate production fleet-minimum policy.
                scenario.cgroup = "0::/system.slice/x0x-http-test.service".into();
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
                manifest.assets[0].archive_url = "http-fixture://no-download".into();
                manifest.assets[0].signature_url = "http-fixture://no-download".into();
                let started = tokio::time::Instant::now();
                let (_shutdown_tx, shutdown_watch) = watch::channel(false);
                let runtime = HttpUpgradeRuntime {
                    config,
                    restart_context: listener_restart_context(&data,
                        SocketAddr::from(([127, 0, 0, 1], 12700)), Arc::clone(&shutdown)),
                    apply_lock: Arc::new(Mutex::new(())), shutdown: shutdown_watch,
                    staging: Some(StartupStagingContext {
                        install: install.clone(), identity_root: data.clone(), machine_id: [42; 32],
                        observed: None,
                        clock: Some(Arc::new(move || Ok(crate::upgrade::probe::ProbeClock {
                            boot_id: "http-copied-fixture".into(),
                            monotonic_ms: 1000 + u64::try_from(started.elapsed().as_millis())
                                .map_err(std::io::Error::other)?,
                        }))),
                    }),
                    operation_observer: None,
                    wait_slot: Arc::new(Arc::new(Mutex::new(())).try_lock_owned().unwrap()),
                };
                let release = crate::upgrade::monitor::VerifiedRelease {
                    manifest_json: serde_json::to_vec(&manifest).unwrap(), manifest,
                    signature: Vec::new(), gossip_payload: Vec::new(),
                };
                let mut result = None;
                {
                    // This is the helper called by the actual POST apply route.
                    // The GREEN helper carries the actual owned boot context
                    // and original release bytes through its production gate.
                    let operation = apply_http_release(&runtime, &release, false);
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
