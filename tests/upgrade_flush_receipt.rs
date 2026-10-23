// Expanded in upgrade::shutdown_flush; owned filesystem and injected sinks only.
#[allow(unused_macros)]
macro_rules! flush_receipt_regression_tests {
    () => {
        #[cfg(unix)]
        mod flush_receipt_regressions {
            use super::*;
            use std::sync::atomic::{AtomicBool, Ordering};

            fn fixture() -> tempfile::TempDir {
                let root = std::env::var_os("X0X_UPGRADE_FLUSH_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join("target/upgrade-flush-fixtures")
                    });
                std::fs::create_dir_all(&root).unwrap();
                tempfile::Builder::new()
                    .prefix("receipt-")
                    .tempdir_in(root)
                    .unwrap()
            }

            #[derive(Clone)]
            struct RecordedSink(Arc<Mutex<Vec<u8>>>);

            impl std::io::Write for RecordedSink {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(bytes);
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }

            #[derive(Clone, Copy)]
            enum AfterHookFailure {
                Deadline,
                ReceiptWrite,
                HookTimeout,
            }

            fn failed_receipt_keeps_logging(failure: AfterHookFailure) {
                use crate::upgrade::log_flush;
                use std::io::Write;
                use tracing_subscriber::layer::SubscriberExt;

                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let bytes = Arc::new(Mutex::new(Vec::new()));
                let (mut writer, _guard) =
                    log_flush::acknowledged(RecordedSink(bytes.clone())).unwrap();
                let dispatch = tracing::Dispatch::new(
                    tracing_subscriber::registry()
                        .with(log_flush::FlushLayer::new(vec![writer.clone()]).unwrap()),
                );
                let callback = log_flush::capture(&dispatch).unwrap();
                let hook_callback = callback.clone();
                let hook_root = root.clone();
                let called = Arc::new(AtomicBool::new(false));
                let observed = called.clone();
                let owner = register(
                    root.clone(),
                    Arc::new(move |deadline, stopped| {
                        // This hook represents the flush owner from the stop
                        // onward: everything it does runs behind the hook.
                        stopped.store(true, Ordering::Release);
                        log_flush::flush_captured(&hook_callback, deadline.instant)?;
                        observed.store(true, Ordering::SeqCst);
                        match failure {
                            AfterHookFailure::ReceiptWrite => {
                                // The intent is already durable. Refuse only receipt publication.
                                std::fs::remove_file(hook_root.join(RECORD))?;
                                std::fs::create_dir(hook_root.join(RECORD))?;
                                Ok(())
                            }
                            AfterHookFailure::Deadline => {
                                std::thread::sleep(
                                    deadline.instant.saturating_duration_since(Instant::now())
                                        + Duration::from_millis(20),
                                );
                                Ok(())
                            }
                            AfterHookFailure::HookTimeout => Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "injected hook timeout after the log barrier",
                            )),
                        }
                    }),
                )
                .unwrap();
                writer.write_all(b"before upgrade").unwrap();
                let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                let result =
                    acknowledge_with_limit(&root, binding, || Ok(()), Duration::from_millis(500));
                owner.join_workers();
                assert!(result.is_err(), "fault must refuse the receipt");
                assert!(
                    called.load(Ordering::SeqCst),
                    "hook must complete its log barrier"
                );
                assert!(root.join("upgrade-flush-rollback.json").is_file());
                writer.write_all(b"after rollback").unwrap();
                log_flush::flush_captured(&callback, Instant::now() + Duration::from_secs(5))
                    .unwrap();
                assert_eq!(*bytes.lock().unwrap(), b"before upgradeafter rollback");
            }

            #[test]
            fn flush_receipt_deadline_after_hook_preserves_logging() {
                failed_receipt_keeps_logging(AfterHookFailure::Deadline);
            }

            #[test]
            fn flush_receipt_write_failure_after_hook_preserves_logging() {
                failed_receipt_keeps_logging(AfterHookFailure::ReceiptWrite);
            }

            #[test]
            fn flush_receipt_hook_timeout_preserves_logging() {
                failed_receipt_keeps_logging(AfterHookFailure::HookTimeout);
            }

            #[test]
            fn ordinary_shutdown_closes_flush_admission_before_releasing_its_owner() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let called = Arc::new(AtomicBool::new(false));
                let observed = Arc::clone(&called);
                let owner = register(
                    root.clone(),
                    Arc::new(move |_, _| {
                        observed.store(true, Ordering::SeqCst);
                        Ok(())
                    }),
                )
                .unwrap();
                let pending = reserve(&root).unwrap();
                assert!(!owner.seal_admission());
                assert!(pending.activate().is_err());
                assert!(ensure_ready(&root).is_err());
                let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                assert!(acknowledge(&root, binding, || Ok(())).is_err());
                owner.join_workers();
                assert!(!called.load(Ordering::SeqCst));
                assert!(!root.join(RECORD).exists());
                drop(owner);
                let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
                let reservation = reserve(&root).unwrap();
                reservation.activate().unwrap();
                drop(owner);
                assert!(
                    register(root, Arc::new(|_, _| Ok(()))).is_err(),
                    "dropping an armed owner must not admit a second shutdown owner"
                );
                drop(reservation);
            }

            #[test]
            fn flush_receipt_rejects_changed_transaction_generation_or_plan() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
                let reservation = reserve(&root).unwrap();
                reservation.activate().unwrap();
                assert!(
                    owner.seal_admission(),
                    "admitted replacement retains shutdown custody"
                );
                let binding =
                    Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"frozen plan").unwrap();
                assert!(acknowledge(&root, binding.clone(), || Ok(())).is_err());
                let receipt =
                    acknowledge_reserved(&root, binding.clone(), || Ok(()), &reservation).unwrap();
                assert!(
                    acknowledge_reserved(&root, binding.clone(), || Ok(()), &reservation).is_err()
                );
                receipt.authorize(&binding).unwrap();
                for changed in [
                    Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"frozen plan").unwrap(),
                    Binding::new(binding.transaction_id.clone(), 2, &"frozen plan").unwrap(),
                    Binding::new(binding.transaction_id.clone(), 1, &"different plan").unwrap(),
                ] {
                    assert!(receipt.authorize(&changed).is_err());
                }
                owner.join_workers();
            }

            #[test]
            fn startup_clears_stale_flush_records_of_a_gone_owner() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                // Debris of an interrupted flush: a receipt-less record plus a
                // rollback marker. check_previous refuses every later upgrade
                // while either survives.
                let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                let (boot_id, _) = clock().unwrap();
                let record = serde_json::json!({
                    "schema_version": 1, "record_kind": "shutdown_flush",
                    "binding": binding, "boot_id": boot_id,
                    "deadline_ms": u64::MAX, "receipt_id": null, "rollback_reason": null,
                });
                crate::upgrade::journal::write_auxiliary_record(
                    &root.join(RECORD),
                    &record,
                    validate,
                )
                .unwrap();
                crate::upgrade::journal::write_auxiliary_record(
                    &root.join(ROLLBACK_RECORD),
                    &serde_json::json!({
                        "schema_version": 1, "record_kind": "shutdown_flush",
                        "binding": binding, "boot_id": boot_id,
                        "deadline_ms": u64::MAX, "receipt_id": null,
                        "rollback_reason": "interrupted by SIGTERM",
                    }),
                    validate,
                )
                .unwrap();
                let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
                assert!(
                    ensure_ready(&root).is_err(),
                    "stale debris must refuse the flush gate before the cleanup"
                );
                clear_stale_records(&root);
                assert!(!root.join(RECORD).exists());
                assert!(!root.join(ROLLBACK_RECORD).exists());
                // With the debris cleared, the flush gate no longer refuses.
                ensure_ready(&root).unwrap();
                drop(owner);
            }

            #[test]
            fn startup_keeps_a_receipt_bearing_flush_record() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let owner = register(root.clone(), Arc::new(|_, _| Ok(()))).unwrap();
                let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                acknowledge(&root, binding, || Ok(())).unwrap();
                owner.join_workers();
                assert!(root.join(RECORD).is_file());
                clear_stale_records(&root);
                assert!(
                    root.join(RECORD).is_file(),
                    "a completed receipt is evidence, not debris"
                );
            }

            #[test]
            fn failed_release_hold_refuses_the_same_release_and_survives_startup_cleanup() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                hold_failed_release(&root, "2.0.0", "injected started flush failure").unwrap();
                // A restart clears the flush debris but must keep the hold.
                clear_stale_records(&root);
                assert!(root.join(HOLD_RECORD).is_file());
                for refused in ["2.0.0", "1.9.9"] {
                    assert_eq!(
                        release_is_held(&root, &semver::Version::parse(refused).unwrap())
                            .unwrap()
                            .as_deref(),
                        Some("2.0.0"),
                        "{refused} must stay refused"
                    );
                }
                // A newer release is the automatic way past the hold.
                assert_eq!(
                    release_is_held(&root, &semver::Version::parse("2.0.1").unwrap()).unwrap(),
                    None
                );
                // The operator's manual clearing: remove the hold file.
                std::fs::remove_file(root.join(HOLD_RECORD)).unwrap();
                assert_eq!(
                    release_is_held(&root, &semver::Version::parse("2.0.0").unwrap()).unwrap(),
                    None
                );
            }

            #[test]
            fn unreadable_failed_release_hold_refuses_instead_of_guessing() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                std::fs::write(root.join(HOLD_RECORD), b"not a hold record").unwrap();
                assert!(
                    release_is_held(&root, &semver::Version::parse("2.0.1").unwrap()).is_err(),
                    "an unreadable hold must refuse every apply, even a newer release"
                );
            }
        }
    };
}
