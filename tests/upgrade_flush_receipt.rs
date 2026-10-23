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
                    Arc::new(move |deadline| {
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
                    Arc::new(move |_| {
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
                let owner = register(root.clone(), Arc::new(|_| Ok(()))).unwrap();
                let reservation = reserve(&root).unwrap();
                reservation.activate().unwrap();
                drop(owner);
                assert!(
                    register(root, Arc::new(|_| Ok(()))).is_err(),
                    "dropping an armed owner must not admit a second shutdown owner"
                );
                drop(reservation);
            }

            #[test]
            fn flush_receipt_rejects_changed_transaction_generation_or_plan() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let owner = register(root.clone(), Arc::new(|_| Ok(()))).unwrap();
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
        }
    };
}
