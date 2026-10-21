// Expanded inside routes::upgrade::tests. Only the raw current-path observation
// is injected. Actual restart planning, install locks and record readers run;
// the existing apply hook stops before download, candidate execution or swap.
#[allow(unused_macros)]
macro_rules! staging_canonical_regression_tests {
    () => {
        #[cfg(unix)]
        mod staging_canonical_regressions {
            use super::*;
            use crate::upgrade::{apply, pair, probe, staging};
            use sha2::Digest;
            use std::collections::BTreeMap;
            use std::fs::{self, File, OpenOptions};
            use std::future::Future;
            use std::os::unix::{
                fs::{symlink, MetadataExt},
                prelude::PermissionsExt,
            };
            use std::path::{Path, PathBuf};
            use std::pin::Pin;
            use std::sync::Mutex as StdMutex;
            use std::time::Instant;

            struct Fixture {
                install: PathBuf,
                alias: PathBuf,
                other: PathBuf,
                data: PathBuf,
                request: staging::StagingRequest,
                manifest: ReleaseManifest,
                attempts: Arc<StdMutex<Vec<PathBuf>>>,
                _apply: apply::apply_attempt_seam::Guard,
                _readback: restart::systemd_readback_seam::Guard,
                root: tempfile::TempDir,
            }

            fn lock_path(path: &Path) -> PathBuf {
                let mut name = path.file_name().unwrap().to_os_string();
                name.push(".upgrade.lock");
                path.with_file_name(name)
            }

            fn identity(path: &Path) -> (u64, u64) {
                let metadata = fs::metadata(path).unwrap();
                (metadata.dev(), metadata.ino())
            }

            fn bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
                let mut result = BTreeMap::new();
                for entry in fs::read_dir(root).unwrap() {
                    let entry = entry.unwrap();
                    let kind = entry.file_type().unwrap();
                    if kind.is_dir() {
                        result.extend(bytes(&entry.path()));
                    } else if kind.is_file() {
                        result.insert(entry.path(), fs::read(entry.path()).unwrap());
                    }
                }
                result
            }

            impl Fixture {
                fn new() -> Self {
                    let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                                .join(".planning/upgrade-canonical-fixtures")
                        });
                    fs::create_dir_all(&base).unwrap();
                    let root = tempfile::Builder::new()
                        .prefix("raw-path-")
                        .tempdir_in(base)
                        .unwrap();
                    let path = root.path().canonicalize().unwrap();
                    for name in ["canonical", "alias", "other", "data", "identity"] {
                        fs::create_dir(path.join(name)).unwrap();
                    }
                    let install = path.join("canonical/x0xd");
                    let alias = path.join("alias/launch-x0xd");
                    let other = path.join("other/x0xd");
                    fs::write(&install, b"canonical installed bytes").unwrap();
                    fs::write(&other, b"different installed bytes").unwrap();
                    for target in [&install, &other] {
                        fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
                    }
                    symlink(&install, &alias).unwrap();
                    for target in [&install, &alias, &other] {
                        drop(crate::upgrade::acquire_host_upgrade_lock(target).unwrap());
                    }
                    let data = path.join("data");
                    let mut manifest = manifest_for_this_platform("9.9.9");
                    manifest.timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let request = staging::StagingRequest {
                        install: install.clone(),
                        data_root: data.clone(),
                        identity_root: path.join("identity"),
                        machine_id: [42; 32],
                        version: manifest.version.clone(),
                        manifest_sha256: sha2::Sha256::digest(
                            serde_json::to_vec(&manifest).unwrap(),
                        )
                        .into(),
                        archive_sha256: manifest.assets[0].archive_sha256,
                        window_minutes: 0,
                    };
                    {
                        let _held = crate::upgrade::acquire_host_upgrade_lock(&install).unwrap();
                        assert_eq!(
                            staging::observe(&request, &Self::clock()).unwrap(),
                            staging::Decision::Due
                        );
                    }
                    // No manager authority is fabricated for the alias. The real
                    // unsupervised planner accepts either path's existing parent;
                    // systemd's test-only exact-path comparator is not involved.
                    let readback = restart::systemd_readback_seam::install(
                        restart::systemd_readback_seam::Scenario {
                            cgroup: "0::/".into(),
                            invocation_id: None,
                            calls: vec![restart::systemd_readback_seam::ReadbackCall {
                                show_output: String::new(),
                                monotonic_now_us: 0,
                            }],
                        },
                    );
                    assert!(
                        !restart::is_supervised(&restart::SupervisionSignals::sample()),
                        "inert fixture must not invoke a real service manager"
                    );
                    let attempts = Arc::new(StdMutex::new(Vec::new()));
                    let observed = Arc::clone(&attempts);
                    let apply =
                        apply::apply_attempt_seam::install(Box::new(move |plan, manifest| {
                            observed.lock().unwrap().push(plan.executable.clone());
                            x0x::upgrade::UpgradeResult::Success {
                                version: manifest.version.clone(),
                            }
                        }));
                    Self {
                        install,
                        alias,
                        other,
                        data,
                        request,
                        manifest,
                        attempts,
                        _apply: apply,
                        _readback: readback,
                        root,
                    }
                }

                fn clock() -> probe::ProbeClock {
                    probe::ProbeClock {
                        boot_id: "canonical-staging-fixture".into(),
                        monotonic_ms: 1000,
                    }
                }

                fn upgrader(&self) -> AutoApplyUpgrader {
                    AutoApplyUpgrader::new("x0xd")
                        .with_restart_on_success(false)
                        .with_restart_context(listener_restart_context(
                            &self.data,
                            SocketAddr::from(([127, 0, 0, 1], 1)),
                            Arc::new(|| {}),
                        ))
                        .with_staging_request(self.request.clone())
                        .with_staging_clock(Some(Arc::new(|| Ok(Self::clock()))))
                }

                fn seed_probe(&self, install: &Path, waiting: bool) -> PathBuf {
                    let state = probe::ProbeState {
                        schema_version: 1,
                        record_kind: "probe".into(),
                        install: install.to_path_buf(),
                        version: self.manifest.version.clone(),
                        platform: self.manifest.assets[0].target.clone(),
                        archive_sha256: self.manifest.assets[0].archive_sha256,
                        transaction_id: "12121212-1212-4212-8212-121212121212".into(),
                        attempt: 1,
                        phase: if waiting {
                            probe::ProbePhase::InterruptedWait
                        } else {
                            probe::ProbePhase::FailedHold
                        },
                        cause: Some(if waiting {
                            probe::ProbeCause::Timeout
                        } else {
                            probe::ProbeCause::NonzeroExit
                        }),
                        last_pid: None,
                        boot_id: "canonical-previous-boot".into(),
                        retry_remaining_ms: if waiting { 1_800_000 } else { 0 },
                        retry_deadline_ms: if waiting { 1_800_001 } else { 0 },
                        daemon_sha256: None,
                        cli_sha256: None,
                    };
                    let path = probe::state_path(install).unwrap();
                    fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
                    assert!(probe::read_state(install).unwrap().is_some());
                    path
                }
            }

            async fn finish<F: Future>(mut operation: Pin<&mut F>) -> F::Output {
                let deadline = Instant::now() + Duration::from_secs(20);
                loop {
                    assert!(Instant::now() < deadline, "actual operation did not drain");
                    tokio::select! { biased;
                        result = operation.as_mut() => return result,
                        _ = tokio::task::yield_now() => {}
                    }
                }
            }

            async fn while_held<F: Future>(mut operation: Pin<&mut F>) -> Option<F::Output> {
                let deadline = Instant::now() + Duration::from_millis(250);
                while Instant::now() < deadline {
                    tokio::select! { biased;
                        result = operation.as_mut() => return Some(result),
                        _ = tokio::task::yield_now() => {}
                    }
                }
                None
            }

            #[tokio::test(flavor = "current_thread")]
            async fn staging_canonical_apply_uses_the_owned_lock_and_target_for_raw_leaf_alias() {
                for spelling in ["canonical", "leaf", "directory"] {
                    let f = Fixture::new();
                    let raw = match spelling {
                        "canonical" => f.install.clone(),
                        "leaf" => f.alias.clone(),
                        _ => {
                            let directory = f.root.path().join("directory-alias");
                            symlink(f.install.parent().unwrap(), &directory).unwrap();
                            directory.join("x0xd")
                        }
                    };
                    assert_eq!(raw.canonicalize().unwrap(), f.install);
                    assert_eq!(
                        identity(&lock_path(&raw)) == identity(&lock_path(&f.install)),
                        spelling != "leaf"
                    );
                    let _raw = apply::current_binary_path_seam::install(raw.clone());
                    assert_eq!(apply::current_binary_path().unwrap(), raw);
                    let upgrader = f.upgrader();
                    let before = bytes(f.root.path());
                    let held = crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                    let operation = upgrader.apply_upgrade_from_manifest(&f.manifest);
                    tokio::pin!(operation);
                    let early = while_held(operation.as_mut()).await;
                    let completed_early = early.is_some();
                    let during = bytes(f.root.path());
                    drop(held);
                    let result = match early {
                        Some(result) => result,
                        None => finish(operation.as_mut()).await,
                    };
                    // Assert only after the real lock holder is released and the
                    // operation drains, including on an intended RED result.
                    assert!(
                        !completed_early,
                        "{spelling}: canonical lock did not exclude actual apply"
                    );
                    assert_eq!(during, before);
                    assert!(
                        matches!(result, Ok(x0x::upgrade::UpgradeResult::Success { .. })),
                        "{result:?}"
                    );
                    assert_eq!(*f.attempts.lock().unwrap(), vec![f.install.clone()]);
                    assert_eq!(fs::read_link(&f.alias).unwrap(), f.install);
                    assert_eq!(fs::read(&f.install).unwrap(), b"canonical installed bytes");
                }
            }

            #[tokio::test(flavor = "current_thread")]
            async fn staging_canonical_retry_cannot_update_shared_probe_state_under_an_alias_lock()
            {
                let f = Fixture::new();
                let state = f.seed_probe(&f.install, true);
                let _raw = apply::current_binary_path_seam::install(f.alias.clone());
                let before = fs::read(&state).unwrap();
                let upgrader = f.upgrader();
                let held = crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                let operation = upgrader.probe_retry_delay(&f.manifest.version);
                tokio::pin!(operation);
                let early = while_held(operation.as_mut()).await;
                let completed_early = early.is_some();
                let during = fs::read(&state).unwrap();
                drop(held);
                let result = match early {
                    Some(result) => result,
                    None => finish(operation.as_mut()).await,
                };
                assert!(
                    !completed_early,
                    "retry inspected canonical records under a different lock"
                );
                assert_eq!(during, before);
                assert!(result.unwrap().is_some());
                assert_ne!(
                    fs::read(&state).unwrap(),
                    before,
                    "positive control must acknowledge the new boot"
                );
                assert!(f.attempts.lock().unwrap().is_empty());
            }

            #[tokio::test(flavor = "current_thread")]
            async fn staging_canonical_changed_raw_target_refuses_before_probe_or_receipt_writes() {
                for entry in ["wait", "apply", "retry"] {
                    let f = Fixture::new();
                    f.seed_probe(&f.other, true);
                    fs::remove_file(&f.alias).unwrap();
                    symlink(&f.other, &f.alias).unwrap();
                    let _raw = apply::current_binary_path_seam::install(f.alias.clone());
                    let before = bytes(f.root.path());
                    let upgrader = f.upgrader();
                    let refused = if entry == "wait" {
                        let (_sender, mut shutdown) = tokio::sync::watch::channel(false);
                        let operation = upgrader.wait_for_staging(&mut shutdown);
                        tokio::pin!(operation);
                        finish(operation.as_mut()).await.is_err()
                    } else if entry == "retry" {
                        let operation = upgrader.probe_retry_delay(&f.manifest.version);
                        tokio::pin!(operation);
                        finish(operation.as_mut()).await.is_err()
                    } else {
                        let operation = upgrader.apply_upgrade_from_manifest(&f.manifest);
                        tokio::pin!(operation);
                        finish(operation.as_mut()).await.is_err()
                    };
                    assert!(
                        refused,
                        "fresh raw observation must not be replaced by the gate target"
                    );
                    assert_eq!(
                        bytes(f.root.path()),
                        before,
                        "mismatch must precede even retry clock writes"
                    );
                    assert!(f.attempts.lock().unwrap().is_empty());
                }
            }

            #[tokio::test(flavor = "current_thread")]
            async fn staging_canonical_missing_raw_target_cannot_fall_back_to_the_gate() {
                let f = Fixture::new();
                fs::remove_file(&f.alias).unwrap();
                let _raw = apply::current_binary_path_seam::install(f.alias.clone());
                let before = bytes(f.root.path());
                let upgrader = f.upgrader();
                let operation = upgrader.apply_upgrade_from_manifest(&f.manifest);
                tokio::pin!(operation);
                assert!(finish(operation.as_mut()).await.is_err());
                assert_eq!(bytes(f.root.path()), before);
                assert!(f.attempts.lock().unwrap().is_empty());
            }

            #[tokio::test(flavor = "current_thread")]
            async fn staging_canonical_alias_reads_the_same_hold_and_pair_intent() {
                for pending_pair in [false, true] {
                    let f = Fixture::new();
                    assert_eq!(
                        probe::state_path(&f.alias).unwrap(),
                        probe::state_path(&f.install).unwrap()
                    );
                    assert_eq!(
                        pair::pair_pending_path(&f.alias).unwrap(),
                        pair::pair_pending_path(&f.install).unwrap()
                    );
                    if pending_pair {
                        fs::write(
                            pair::pair_pending_path(&f.install).unwrap(),
                            b"unresolved pair intent",
                        )
                        .unwrap();
                    } else {
                        f.seed_probe(&f.install, false);
                    }
                    let _raw = apply::current_binary_path_seam::install(f.alias.clone());
                    let before = bytes(f.root.path());
                    let upgrader = f.upgrader();
                    let operation = upgrader.apply_upgrade_from_manifest(&f.manifest);
                    tokio::pin!(operation);
                    assert!(finish(operation.as_mut()).await.is_err());
                    assert_eq!(bytes(f.root.path()), before);
                    assert!(f.attempts.lock().unwrap().is_empty());
                }
            }

            #[test]
            fn staging_canonical_shared_lock_still_serializes_an_absent_target() {
                let f = Fixture::new();
                let path = lock_path(&f.install);
                fs::write(&path, b"persistent lock sentinel").unwrap();
                let original = identity(&path);
                fs::remove_file(&f.install).unwrap();
                let held = crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                let contender = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .unwrap();
                assert!(matches!(
                    contender.try_lock(),
                    Err(std::fs::TryLockError::WouldBlock)
                ));
                drop(held);
                drop(contender);
                let reacquired: File =
                    crate::upgrade::acquire_host_upgrade_lock(&f.install).unwrap();
                assert_eq!(identity(&path), original);
                assert_eq!(fs::read(&path).unwrap(), b"persistent lock sentinel");
                assert!(!f.install.exists());
                drop(reacquired);
            }
        }
    };
}
