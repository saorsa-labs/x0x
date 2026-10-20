// Included and invoked inside server::routes::upgrade::tests by the lead.
// This standalone integration target deliberately has no tests: the expansion
// needs the existing private release/readback/apply seams. They replace external
// I/O and destructive execution; the real startup/apply preflight still runs.
// No Agent, real daemon, manager command, network or binary replacement runs.
#[allow(unused_macros)]
macro_rules! staging_regression_tests {
    () => {
        #[tokio::test(start_paused = true)]
        async fn staging_startup_waits_before_applying_once_within_its_window() {
            let fixture_root = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning")
                        .join("upgrade-staging-fixtures")
                });
            std::fs::create_dir_all(&fixture_root).expect("owned staging fixture root");
            let data_dir = tempfile::Builder::new()
                .prefix("startup-window-")
                .tempdir_in(&fixture_root)
                .expect("owned staging data directory");

            // Disable only systemd's independent start-rate wait. Any wait
            // observed below must come from the configured rollout window.
            let _readback = restart::systemd_readback_seam::install(one_call_scenario("0", "5"));
            let attempts = Arc::new(AtomicU64::new(0));
            let hook_attempts = Arc::clone(&attempts);
            let _apply = crate::upgrade::apply::apply_attempt_seam::install(Box::new(
                move |_plan, manifest| {
                    hook_attempts.fetch_add(1, Ordering::SeqCst);
                    x0x::upgrade::UpgradeResult::Success {
                        version: manifest.version.clone(),
                    }
                },
            ));
            let mut manifest = manifest_for_this_platform("9.9.9");
            manifest.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("current release timestamp")
                .as_secs();
            let _release =
                startup_release_seam::install(crate::upgrade::monitor::VerifiedRelease {
                    manifest,
                    manifest_json: Vec::new(),
                    signature: Vec::new(),
                    gossip_payload: Vec::new(),
                });
            let mut config = DaemonConfig {
                data_dir: data_dir.path().to_path_buf(),
                ..Default::default()
            };
            config.update.rollout_window_minutes = 60;
            let (runtime, _shutdown_tx) = e2e_startup_runtime(data_dir.path());
            let apply_lock = Arc::clone(&runtime.upgrade_apply_lock);
            let started = tokio::time::Instant::now();
            let startup = run_startup_update_check(&config, None, Some(runtime));
            tokio::pin!(startup);

            // Timeout borrows the same pinned future. It must not cancel the
            // waiting startup operation before the eventual-apply control.
            let early = tokio::time::timeout(Duration::from_secs(1), startup.as_mut()).await;
            let early_attempts = attempts.load(Ordering::SeqCst);
            let lock_was_available = apply_lock.try_lock().is_ok();
            let (completed_early, result) = match early {
                Ok(result) => (true, result),
                Err(_) => {
                    let remaining = Duration::from_secs(60 * 60).saturating_sub(started.elapsed());
                    let result = tokio::time::timeout(remaining, startup.as_mut())
                        .await
                        .expect("the same startup operation must finish within its rollout window");
                    (false, result)
                }
            };

            assert_eq!(
                early_attempts, 0,
                "a positive rollout window must prevent immediate destructive admission"
            );
            assert!(!completed_early, "startup must retain the pending apply");
            assert!(lock_was_available, "the wait must release the apply mutex");
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                1,
                "the retained startup operation must eventually apply exactly once"
            );
            assert!(
                matches!(&result, Ok(Some(version)) if version == "9.9.9"),
                "the due release must apply successfully: {result:?}"
            );
            assert!(started.elapsed() <= Duration::from_secs(60 * 60));
        }
    };
}
