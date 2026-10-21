// Expanded inside upgrade::apply::tests. Uses the actual deferred owner and
// actual replacement worker; only the final external restart is intercepted.
#[allow(unused_macros)]
macro_rules! http_custody_regression_tests {
    () => {
        #[cfg(unix)]
        mod http_custody_regressions {
            use super::*;
            use std::time::Duration;
            struct CustodyDrain {
                release: Option<std::sync::mpsc::Sender<()>>,
                worker_done: std::sync::mpsc::Receiver<()>,
                restart_done: std::sync::mpsc::Receiver<()>,
            }
            impl CustodyDrain {
                fn release(&mut self) { if let Some(sender)=self.release.take() { let _=sender.send(()); } }
            }
            impl Drop for CustodyDrain {
                fn drop(&mut self) {
                    self.release();
                    // Bounded failure cleanup precedes hook/root destruction.
                    let _=self.worker_done.recv_timeout(Duration::from_secs(6));
                    let _=self.restart_done.recv_timeout(Duration::from_secs(2));
                }
            }

            #[tokio::test(flavor="current_thread")]
            async fn http_deferred_actual_owner_survives_cancellation_between_pair_renames() {
                let base=std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR").map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".planning/upgrade-http-fixtures"));
                std::fs::create_dir_all(&base).unwrap();
                let root=tempfile::Builder::new().prefix("http-custody-").tempdir_in(base).unwrap();
                let root_path=root.path().canonicalize().unwrap();
                let scratch=root_path.join("scratch"); std::fs::create_dir(&scratch).unwrap();
                let daemon=root_path.join("x0xd"); let cli=root_path.join("x0x");
                std::fs::write(&daemon,b"old-daemon").unwrap(); std::fs::write(&cli,b"old-cli").unwrap();
                let incoming=scratch.join("daemon"); let incoming_cli=scratch.join("cli");
                std::fs::write(&incoming,b"new-daemon").unwrap(); std::fs::write(&incoming_cli,b"new-cli").unwrap();
                let plan=restart::RestartPlan {
                    mode:restart::RestartMode::TransactionalHandoff, supervised_exit_code:None, supervision_signal:None,
                    executable:daemon.clone(), argv:vec![daemon.to_str().unwrap().into()], cwd:root_path.clone(),
                    data_root:root_path.clone(), api_addr:"127.0.0.1:1".parse().unwrap(), launchd_verified:None, systemd_verified:None,
                };
                let count=Arc::new(std::sync::atomic::AtomicUsize::new(0)); let counted=Arc::clone(&count);
                let (restarted,mut restart_events)=tokio::sync::mpsc::unbounded_channel();
                let (restart_done,restart_done_rx)=std::sync::mpsc::channel();
                let observed_scratch=scratch.clone();
                let _restart=http_deferred_restart_seam::install(daemon.clone(),Arc::new(move |plan,version| {
                    let observation=(plan.executable.clone(),version.to_string(),observed_scratch.exists());
                    counted.fetch_add(1,Ordering::SeqCst); let _=restarted.send(observation);
                    // Last callback operation. Assertions run on the test
                    // thread after all owned filesystem observation completes.
                    let _=restart_done.send(());
                }));
                // The actual production owner parks before any mutation, then
                // waits its real750ms after the worker signals successful apply.
                let on_success=arm_http_deferred_restart_owner("x0xd".into(),false,RestartContext::default(),plan,"2.0.0".into()).unwrap();
                REPLACE_HOOK_INIT.call_once(|| { tracing::subscriber::set_global_default(PauseAtReplacingBinary).unwrap(); });
                let (entered_tx,entered_rx)=tokio::sync::oneshot::channel();
                let (release_tx,release_rx)=std::sync::mpsc::channel();
                REPLACE_HOOKS.lock().unwrap().insert(daemon.clone(),ReplaceHook { entered:entered_tx, release:release_rx });
                let _pause=ReplaceHookGuard {target:daemon.clone()};
                let wait_lock=Arc::new(tokio::sync::Mutex::new(()));
                let mut permit=ReleasePermit::for_http(Arc::new(Arc::clone(&wait_lock).try_lock_owned().unwrap()));
                let (worker_tx,mut worker_rx)=tokio::sync::mpsc::unbounded_channel();
                let (worker_done,worker_done_rx)=std::sync::mpsc::channel();
                permit.observer=Some(Arc::new(move |entered| {
                    let _=worker_tx.send(entered); if !entered { let _=worker_done.send(()); }
                }));
                let mut drain=CustodyDrain {release:Some(release_tx),worker_done:worker_done_rx,restart_done:restart_done_rx};
                let mut operation=Box::pin(apply_replacements_with_permit(
                    Upgrader::new(daemon.clone(),semver::Version::new(1,0,0)),incoming,semver::Version::new(2,0,0),
                    Some((Upgrader::new(cli.clone(),semver::Version::new(1,0,0)),incoming_cli)),
                    TempDirGuard {path:scratch.clone()},Some(on_success),None,Some(&permit),
                ));
                tokio::time::timeout(Duration::from_secs(5),async {
                    tokio::select! { result=operation.as_mut()=>panic!("replacement ended before pause: {result:?}"), entered=entered_rx=>entered.unwrap() }
                }).await.unwrap();
                let mid_cli=std::fs::read(&cli); let mid_daemon=std::fs::read(&daemon);
                let early_restarts=count.load(Ordering::SeqCst);
                permit.cancel(); permit.release_http_wait_slot(); drop(operation);
                let capacity_retained=Arc::clone(&wait_lock).try_lock_owned().is_err();
                drain.release();
                let mut saw_entry=false;
                tokio::time::timeout(Duration::from_secs(5),async {
                    loop { match worker_rx.recv().await { Some(true)=>saw_entry=true,Some(false)=>break,None=>panic!("worker observer disappeared") } }
                }).await.unwrap();
                let capacity_released=Arc::clone(&wait_lock).try_lock_owned().is_ok();
                let (restart_target,restart_version,scratch_present)=tokio::time::timeout(Duration::from_secs(5),restart_events.recv()).await.unwrap().unwrap();
                drop(drain);
                assert!(saw_entry); assert!(capacity_retained); assert!(capacity_released);
                assert_eq!(mid_cli.unwrap(),b"new-cli"); assert_eq!(mid_daemon.unwrap(),b"old-daemon");
                assert_eq!(early_restarts,0); assert_eq!(restart_target,daemon); assert_eq!(restart_version,"2.0.0");
                assert!(!scratch_present,"scratch must be gone before external restart");
                assert_eq!(std::fs::read(&daemon).unwrap(),b"new-daemon"); assert_eq!(std::fs::read(&cli).unwrap(),b"new-cli");
                assert_eq!(std::fs::read(daemon.with_extension("backup")).unwrap(),b"old-daemon");
                assert_eq!(std::fs::read(cli.with_extension("backup")).unwrap(),b"old-cli");
                assert!(!scratch.exists());
                tokio::time::sleep(HTTP_DEFERRED_RESTART_DELAY+Duration::from_millis(100)).await;
                assert_eq!(count.load(Ordering::SeqCst),1); assert!(restart_events.try_recv().is_err());
            }
        }
    };
}
