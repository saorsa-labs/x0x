// Expanded in server::upgrade_flush. Exercises the real authenticated handler
// with offline state and owned producers. The socket case requires Linux isolation.
#[allow(unused_macros)]
macro_rules! arm_flush_regression_tests {
    () => {
        #[cfg(test)]
        mod arm_flush_regressions {
            use super::*;
            use serde_json::{json, Value};
            use std::sync::atomic::{AtomicBool, Ordering};

            fn fixture() -> (tempfile::TempDir, Value, Value, ControlContext) {
                let base = std::env::var_os("X0X_UPGRADE_FLUSH_EVIDENCE_DIR").map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".planning/upgrade-flush-fixtures"));
                std::fs::create_dir_all(&base).unwrap();
                let dir = tempfile::Builder::new().prefix("arm-").tempdir_in(base).unwrap();
                let root = dir.path().canonicalize().unwrap();
                let executable = crate::upgrade::apply::current_binary_path().unwrap();
                let artifact = |name: &str, target: PathBuf| json!({
                    "target_path": target, "staged_path": root.join(format!("{name}.staged")),
                    "backup_path": root.join(format!("{name}.backup")),
                    "previous_sha256": vec![1_u8; 32], "candidate_sha256": vec![2_u8; 32],
                });
                let journal = json!({
                    "schema_version": 1, "record_kind": "journal", "sequence": 7,
                    "transaction_id": uuid::Uuid::new_v4().to_string(), "generation": 3,
                    "phase": "swapped_cli", "cause": null,
                    "daemon_progress": {"swapped": true, "restored": false, "observed_sha256": vec![2_u8; 32]},
                    "cli_progress": {"swapped": true, "restored": false, "observed_sha256": vec![2_u8; 32]},
                    "plan": {
                        "previous_version": "1.0.0", "candidate_version": "2.0.0", "manifest_sha256": vec![3_u8; 32],
                        "daemon": artifact("daemon", executable.clone()), "cli": artifact("cli", root.join("x0x")),
                        "participants": [{
                            "instance_id": "alice", "executable": executable, "data_root": root,
                            "identity_root": root, "cwd": root, "argv": ["x0xd"], "env": {},
                            "old_pid": std::process::id(), "process_start": process_start().unwrap(), "was_running": true,
                            "boot_id": crate::upgrade::probe::ProbeClock::now().unwrap().boot_id,
                            "restart": {"mode": "SupervisedExit", "supervised_exit_code": 75,
                                "supervision_signal": "fixture", "launchd_verified": null,
                                "systemd_verified": null, "launcher": null}
                        }]
                    }
                });
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                let request = json!({"token": "owned fixture credential", "instance_id": "alice",
                    "transaction_id": journal["transaction_id"], "generation": 3, "plan": journal["plan"]});
                let state = ControlContext { api_token: "owned fixture credential".into(),
                    api_address: "127.0.0.1:1".parse().unwrap(), identity_root: root };
                (dir, journal, request, state)
            }

            #[test]
            fn arm_flush_auth_and_frozen_binding_precede_the_actual_flush() {
                let (dir, mut journal, mut request, state) = fixture();
                let root = dir.path().canonicalize().unwrap();
                journal["plan"]["participants"][0]["restart"]["mode"] = json!("TransactionalHandoff");
                request["plan"] = journal["plan"].clone();
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let counted = Arc::clone(&calls);
                let owner = shutdown_flush::register(root.clone(), Arc::new(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst); Ok(())
                })).unwrap();
                for (field, value) in [
                    ("token", json!("wrong credential")),
                    ("transaction_id", json!(uuid::Uuid::new_v4().to_string())),
                    ("generation", json!(4)), ("instance_id", json!("another participant")),
                    ("start_apply", json!(true)),
                ] {
                    let mut changed = request.clone(); changed[field] = value;
                    assert!(arm(&state, &root, &serde_json::to_vec(&changed).unwrap()).is_err(), "{field}");
                }
                let mut changed = request.clone(); changed["plan"]["candidate_version"] = json!("3.0.0");
                assert!(arm(&state, &root, &serde_json::to_vec(&changed).unwrap()).is_err());
                let mut unsupported = journal.clone();
                unsupported["plan"]["participants"][0]["restart"]["mode"] = json!("LauncherChild");
                unsupported["plan"]["participants"][0]["restart"]["launcher"] = json!({
                    "executable": root.join("launcher"), "argv": ["launcher"], "pid": null,
                    "process_start": null, "boot_id": "fixture-boot", "manager_exit_code": 0 });
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &unsupported).unwrap();
                let mut unsupported_request = request.clone(); unsupported_request["plan"] = unsupported["plan"].clone();
                assert_eq!(arm(&state, &root, &serde_json::to_vec(&unsupported_request).unwrap()).unwrap_err().kind(), io::ErrorKind::Unsupported);
                journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert!(!root.join(shutdown_flush::RECORD).exists());
                assert!(!root.join(journal::HANDOFF_FILE_NAME).exists());
                let receipt = arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap();
                owner.join_workers();
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let plan: journal::FrozenPlan = serde_json::from_value(journal["plan"].clone()).unwrap();
                let binding = shutdown_flush::Binding::new(request["transaction_id"].as_str().unwrap().into(),
                    3, &("alice", plan.clone())).unwrap();
                receipt.authorize(&binding).unwrap();
                let other = shutdown_flush::Binding::new(binding.transaction_id.clone(), 3, &("other", plan)).unwrap();
                assert!(receipt.authorize(&other).is_err());
                let journal::RecordRead::Handoff(handoff) = journal::read_boot_records(&root).handoff else { panic!("missing handoff") };
                assert_eq!(handoff.legacy["mode"], json!("TransactionalHandoff"));
                let saved: Value = serde_json::from_slice(&std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                assert!(saved["receipt_id"].as_str().is_some());
                assert_eq!(saved["binding"], serde_json::to_value(binding).unwrap());
            }

            #[test]
            fn arm_flush_refuses_a_different_old_process_even_in_a_matching_plan() {
                for (field, value) in [("old_pid", json!(u32::MAX)), ("boot_id", json!("different-boot")),
                    ("process_start", json!(0)), ("was_running", json!(false)),
                    ("data_root", json!("/")), ("identity_root", json!("/"))] {
                    let (dir, mut journal, mut request, state) = fixture();
                    let root = dir.path().canonicalize().unwrap();
                    journal["plan"]["participants"][0][field] = value;
                    request["plan"] = journal["plan"].clone();
                    journal::write_record(&root.join(journal::JOURNAL_FILE_NAME), &journal).unwrap();
                    let called = Arc::new(AtomicBool::new(false));
                    let observed = Arc::clone(&called);
                    let owner = shutdown_flush::register(root.clone(), Arc::new(move |_| {
                        observed.store(true, Ordering::SeqCst); Ok(())
                    })).unwrap();
                    assert!(arm(&state, &root, &serde_json::to_vec(&request).unwrap()).is_err());
                    owner.join_workers();
                    assert!(!called.load(Ordering::SeqCst));
                    assert!(!root.join(shutdown_flush::RECORD).exists());
                }
            }

            #[test]
            fn shutdown_state_barrier_refuses_symlinks_without_following_them() {
                let (dir, _, _, _) = fixture();
                std::fs::create_dir(dir.path().join("store")).unwrap();
                std::fs::write(dir.path().join("store/state"), b"accepted state").unwrap();
                let deadline = shutdown_flush::Deadline::for_test(Duration::from_secs(5)).unwrap();
                sync_tree(dir.path(), &deadline).unwrap();
                let target = dir.path().join("absent-target");
                std::os::unix::fs::symlink(&target, dir.path().join("store/link")).unwrap();
                assert!(sync_tree(dir.path(), &deadline).is_err());
                assert!(!target.exists());
                assert_eq!(std::fs::read(dir.path().join("store/state")).unwrap(), b"accepted state");
            }

            #[test]
            fn shutdown_state_barrier_stops_after_a_sync_returns_past_the_deadline() {
                let (dir, _, _, _) = fixture();
                let root = dir.path().canonicalize().unwrap();
                let store = root.join("store");
                std::fs::create_dir(&store).unwrap();
                for name in ["first", "second"] { std::fs::write(store.join(name), b"state").unwrap(); }
                let deadline = shutdown_flush::Deadline::for_test(Duration::from_secs(5)).unwrap();
                let mut control = 0;
                sync_tree_with(&store, &deadline, &mut |_| { control += 1; Ok(()) }).unwrap();
                assert_eq!(control, 3);
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let counted = Arc::clone(&calls);
                let (entered, entering) = mpsc::channel();
                let (release, released) = mpsc::channel();
                let released = Mutex::new(released);
                let owner = shutdown_flush::register_with_limit(root.clone(), Arc::new(move |deadline| {
                    sync_tree_with(&store, &deadline, &mut |_| {
                        if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                            let _ = entered.send(());
                            released.lock().unwrap().recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)?;
                        }
                        Ok(())
                    })
                }), Duration::from_secs(2)).unwrap();
                let binding = shutdown_flush::Binding::new(uuid::Uuid::new_v4().to_string(), 1, &"plan").unwrap();
                let (returned, result) = mpsc::channel();
                let caller = std::thread::spawn(move || {
                    let _ = returned.send(shutdown_flush::acknowledge(&root, binding, || Ok(())));
                });
                let did_enter = entering.recv_timeout(Duration::from_secs(5));
                let outcome = result.recv_timeout(Duration::from_secs(5));
                let _ = release.send(());
                caller.join().unwrap();
                owner.join_workers();
                did_enter.unwrap();
                assert_eq!(outcome.unwrap().unwrap_err().kind(), io::ErrorKind::TimedOut);
                assert_eq!(calls.load(Ordering::SeqCst), 1, "no new sync after expiry");
            }

            #[test]
            fn arm_flush_failure_reports_the_started_failure_and_marks_the_upgrade() {
                let (dir, journal, request, state) = fixture();
                let root = dir.path().canonicalize().unwrap();
                // The frozen plan's daemon target is pinned to the running
                // executable by the journal's participant/install consistency
                // rule, so byte restoration is proven at the trigger level
                // (supervised_exit_after_failed_flush_restores_the_previous_binary);
                // here the plan's backup does not exist and the recovery must
                // stay non-destructive.
                let target: PathBuf =
                    serde_json::from_value(journal["plan"]["daemon"]["target_path"].clone())
                        .unwrap();
                let before = std::fs::read(&target).unwrap();
                let owner = shutdown_flush::register(root.clone(), Arc::new(|_| {
                    Err(io::Error::other("injected started flush failure"))
                }))
                .unwrap();
                let failure = arm(&state, &root, &serde_json::to_vec(&request).unwrap()).unwrap_err();
                owner.join_workers();
                // Engineer ruling 23 Oct 2026: a started flush that failed is
                // a FlushFailed (the process exits EX_TEMPFAIL for a restart
                // on the old version), never a plain refusal.
                assert!(matches!(failure, ArmFailure::FlushFailed(_)));
                assert_eq!(std::fs::read(&target).unwrap(), before);
                assert!(root.join(shutdown_flush::ROLLBACK_RECORD).is_file());
                let saved: Value = serde_json::from_slice(
                    &std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                assert!(saved["receipt_id"].is_null());
            }

            // Socket execution belongs to the isolated Linux CI runner.
            #[cfg_attr(not(target_os = "linux"), ignore = "requires isolated Linux network namespace")]
            #[tokio::test]
            async fn arm_flush_unix_transport_receipts_only_after_the_real_shutdown_hook() {
                use std::io::Write;
                use tracing_subscriber::prelude::*;
                struct Sink { bytes: Arc<Mutex<Vec<u8>>>, fail: bool }
                impl Write for Sink {
                    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                        self.bytes.lock().unwrap().extend_from_slice(bytes); Ok(bytes.len())
                    }
                    fn flush(&mut self) -> io::Result<()> {
                        if self.fail { Err(io::Error::other("injected log barrier failure")) } else { Ok(()) }
                    }
                }
                for fail in [false, true] {
                    let (dir, _, mut request, _) = fixture();
                    let root = dir.path().canonicalize().unwrap();
                    let agent = Arc::new(crate::Agent::builder()
                        .with_identity_dir(&root).with_user_key_path(root.join("user.key"))
                        .with_machine_key(root.join("machine.key"))
                        .with_agent_key_path(root.join("agent.key"))
                        .with_agent_cert_path(root.join("agent.cert"))
                        .with_contact_store_path(root.join("contacts.json"))
                        .with_peer_cache_disabled().build().await.unwrap());
                    assert!(agent.network().is_none());
                    let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                        &root, Arc::clone(&agent)).await.unwrap();
                    let mut notified = state.shutdown_notify.subscribe();
                    request["token"] = json!(state.api_token);
                    let bytes = Arc::new(Mutex::new(Vec::new()));
                    let (mut writer, mut guard) = log_flush::acknowledged(Sink { bytes: Arc::clone(&bytes), fail }).unwrap();
                    writer.write_all(b"accepted shutdown log").unwrap();
                    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry()
                        .with(log_flush::FlushLayer::new(vec![writer]).unwrap()));
                    let exit_code = Arc::new(std::sync::atomic::AtomicI32::new(-1));
                    let observed_exit = Arc::clone(&exit_code);
                    let mut owner = tracing::dispatcher::with_default(&dispatch,
                        || FlushOwner::start(&state, &root, &root, shutdown_flush::LIMIT,
                            Arc::new(move |code| observed_exit.store(code, std::sync::atomic::Ordering::SeqCst))))
                        .unwrap();
                    let mut stream = tokio::net::UnixStream::connect(root.join(SOCKET)).await.unwrap();
                    let mut encoded = serde_json::to_vec(&request).unwrap(); encoded.push(b'\n');
                    stream.write_all(&encoded).await.unwrap();
                    tokio::time::timeout(Duration::from_secs(5), notified.changed()).await.unwrap().unwrap();
                    assert!(*notified.borrow());
                    let pending: Value = serde_json::from_slice(&std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                    assert!(pending["receipt_id"].is_null());
                    state.exec_service.shutdown().await;
                    let producers = crate::server::drain_server_tasks(&state, Vec::new()).await;
                    let shutdown = agent.try_shutdown().await.map_err(anyhow::Error::from);
                    let cancel = tokio_util::sync::CancellationToken::new();
                    let reply = async {
                        let mut response = String::new();
                        let read = tokio::time::timeout(Duration::from_secs(5),
                            tokio::io::BufReader::new(stream).read_line(&mut response)).await;
                        cancel.cancel();
                        read.unwrap().unwrap();
                        serde_json::from_str::<Value>(&response).unwrap()
                    };
                    let (response, ()) = tokio::join!(reply, owner.finish(&shutdown, producers, &cancel));
                    owner._registration.join_workers();
                    owner.control.abort(); let _ = (&mut owner.control).await;
                    let saved: Value = serde_json::from_slice(&std::fs::read(root.join(shutdown_flush::RECORD)).unwrap()).unwrap();
                    assert_eq!(*bytes.lock().unwrap(), b"accepted shutdown log");
                    if fail {
                        assert!(response.get("receipt").is_none()); assert!(response["error"].is_string());
                        assert!(saved["receipt_id"].is_null());
                        // Engineer ruling 23 Oct 2026: a started flush that failed
                        // ends the process with EX_TEMPFAIL instead of parking the
                        // daemon with no API and no network.
                        assert_eq!(
                            exit_code.load(std::sync::atomic::Ordering::SeqCst),
                            crate::upgrade::restart::flush_failure_exit_code()
                        );
                    } else {
                        assert_eq!(response["receipt"]["receipt_id"], saved["receipt_id"]);
                        assert!(saved["receipt_id"].is_string());
                        assert_eq!(response["receipt"]["binding"], saved["binding"]);
                        assert_eq!(saved["binding"]["transaction_id"], request["transaction_id"]);
                        assert_eq!(saved["binding"]["generation"], request["generation"]);
                    }
                    let _ = guard.shutdown_until(Instant::now() + Duration::from_secs(1));
                }
            }

            #[tokio::test(start_paused = true)]
            async fn http_drain_timeout_keeps_exit_zero_and_marks_only_the_receipt_unfinished() {
                let server = tokio::spawn(std::future::pending::<std::io::Result<()>>());
                let task = server.abort_handle();
                let (result, drained) = crate::server::drain_http_server(server).await;
                assert!(task.is_finished(), "timed-out HTTP task must be aborted and joined");
                // Ordinary shutdown keeps the clean-stop exit-0 contract
                // (#261/#363): a drain that misses the bound is not a process
                // error. Only the flush receipt sees the unfinished flag.
                assert!(result.is_ok());
                assert!(!drained, "an aborted HTTP producer is not a finished producer");
                assert!(crate::server::combine_server_shutdown_results(result, Ok(())).is_ok());
                let (clean, drained) =
                    crate::server::drain_http_server(tokio::spawn(async { Ok(()) })).await;
                assert!(clean.is_ok());
                assert!(drained);
            }

            #[tokio::test(start_paused = true)]
            async fn shutdown_flush_requires_the_real_server_producer_drain_to_finish() {
                use futures::FutureExt;
                for blocked in [true, false] {
                    let (dir, _, _, _) = fixture();
                    let agent = Arc::new(crate::Agent::builder()
                        .with_identity_dir(dir.path())
                        .with_user_key_path(dir.path().join("user.key"))
                        .with_machine_key(dir.path().join("machine.key"))
                        .with_agent_key_path(dir.path().join("agent.key"))
                        .with_agent_cert_path(dir.path().join("agent.cert"))
                        .with_contact_store_path(dir.path().join("contacts.json"))
                        .with_peer_cache_disabled().build().await.unwrap());
                    assert!(agent.network().is_none());
                    let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                        dir.path(), Arc::clone(&agent)).await.unwrap();
                    state.exec_service.shutdown().await;
                    let (release, released) = tokio::sync::oneshot::channel::<()>();
                    let producer = tokio::spawn(async move { let _ = released.await; })
                        .map(|result| result.map_err(|error| error.to_string())).shared();
                    let tracked = producer.clone();
                    assert!(state.spawn_shielded(async move { tracked.await.unwrap(); }));
                    let task = state.shielded_tasks.lock().unwrap().as_ref().unwrap()
                        .last().unwrap().abort_handle();
                    let mut release = Some(release);
                    if !blocked { release.take().unwrap().send(()).unwrap(); }
                    let start = tokio::time::Instant::now();
                    let complete = crate::server::drain_server_tasks(&state, Vec::new()).await;
                    if let Some(release) = release { release.send(()).unwrap(); }
                    // Join the owned work and observe the exact registered task end.
                    producer.await.unwrap();
                    while !task.is_finished() { tokio::task::yield_now().await; }
                    agent.try_shutdown().await.unwrap();
                    assert_eq!(complete, !blocked);
                    if blocked { assert!(start.elapsed() >= Duration::from_secs(10)); }
                }
            }

            #[tokio::test(start_paused = true)]
            async fn shutdown_flush_counts_an_aborted_grace_straggler_as_unfinished() {
                let (dir, _, _, _) = fixture();
                let agent = Arc::new(crate::Agent::builder()
                    .with_identity_dir(dir.path())
                    .with_user_key_path(dir.path().join("user.key"))
                    .with_machine_key(dir.path().join("machine.key"))
                    .with_agent_key_path(dir.path().join("agent.key"))
                    .with_agent_cert_path(dir.path().join("agent.cert"))
                    .with_contact_store_path(dir.path().join("contacts.json"))
                    .with_peer_cache_disabled().build().await.unwrap());
                assert!(agent.network().is_none());
                let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
                    dir.path(), Arc::clone(&agent)).await.unwrap();
                state.exec_service.shutdown().await;
                let straggler = tokio::spawn(std::future::pending::<()>());
                let abort = straggler.abort_handle();
                let complete = crate::server::drain_server_tasks(&state, vec![straggler]).await;
                assert!(abort.is_finished(), "the straggler must be aborted and joined");
                // ADR 0094 §4: an abort does not stop blocking work the task
                // already started, so a task that missed the grace window is
                // not a finished producer whatever its cancelled JoinError says.
                assert!(!complete, "an aborted grace straggler must not count as finished");
                agent.try_shutdown().await.unwrap();
            }
        }
    };
}
