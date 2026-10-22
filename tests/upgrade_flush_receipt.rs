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
                            .join(".planning/upgrade-flush-fixtures")
                    });
                std::fs::create_dir_all(&root).unwrap();
                tempfile::Builder::new()
                    .prefix("receipt-")
                    .tempdir_in(root)
                    .unwrap()
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
                assert!(!owner.seal_admission());
                assert!(ensure_ready(&root).is_err());
                let binding = Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                assert!(acknowledge(&root, binding, || Ok(())).is_err());
                owner.join_workers();
                assert!(!called.load(Ordering::SeqCst));
                assert!(!root.join(RECORD).exists());
            }

            #[test]
            fn flush_receipt_rejects_changed_transaction_generation_or_plan() {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let owner = register(root.clone(), Arc::new(|_| Ok(()))).unwrap();
                let binding =
                    Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"frozen plan").unwrap();
                let receipt = acknowledge(&root, binding.clone(), || Ok(())).unwrap();
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
