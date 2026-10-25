// Expanded inside the private writer. Only owned memory sinks and threads run.
#[allow(unused_macros)]
macro_rules! log_flush_regression_tests {
    () => {
        #[cfg(test)]
        mod log_flush_regressions {
            use super::*;
            const BOUND: Duration = Duration::from_secs(5);

            struct Sink {
                bytes: Arc<Mutex<Vec<u8>>>,
                failure: Option<bool>,
                blocked: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
            }
            impl Write for Sink {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    if let Some((entered, release)) = self.blocked.take() {
                        let _ = entered.send(());
                        release.recv_timeout(BOUND).map_err(io::Error::other)?;
                    }
                    if self.failure == Some(false) {
                        self.failure = None;
                        return Err(io::Error::other("injected write failure"));
                    }
                    self.bytes.lock().unwrap().extend_from_slice(bytes);
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    if self.failure == Some(true) {
                        self.failure = None;
                        return Err(io::Error::other("injected flush failure"));
                    }
                    Ok(())
                }
            }
            struct Fixture {
                writer: LogWriter,
                guard: Option<LogGuard>,
                bytes: Arc<Mutex<Vec<u8>>>,
                release: mpsc::Sender<()>,
                entered: mpsc::Receiver<()>,
            }
            impl Fixture {
                fn new(failure: Option<bool>, block: bool, capacity: usize) -> Self {
                    Self::with_policy(failure, block, capacity, false)
                }
                fn with_policy(
                    failure: Option<bool>,
                    block: bool,
                    capacity: usize,
                    lossless: bool,
                ) -> Self {
                    let bytes = Arc::new(Mutex::new(Vec::new()));
                    let (release, released) = mpsc::channel();
                    let (entered, entered_rx) = mpsc::channel();
                    let sink = Sink {
                        bytes: bytes.clone(),
                        failure,
                        blocked: block.then_some((entered, released)),
                    };
                    let (writer, guard) = if lossless {
                        start(sink, Write::flush, capacity, true)
                    } else {
                        acknowledged_with_capacity(sink, capacity)
                    }
                    .unwrap();
                    Self {
                        writer,
                        guard: Some(guard),
                        bytes,
                        release,
                        entered: entered_rx,
                    }
                }
                fn block(&mut self) {
                    self.writer.write_all(b"first").unwrap();
                    self.entered.recv_timeout(BOUND).unwrap();
                }
            }
            impl Drop for Fixture {
                fn drop(&mut self) {
                    let _ = self.release.send(());
                    if let Some(mut guard) = self.guard.take() {
                        let worker = guard.worker.take();
                        drop(guard);
                        if let Some(worker) = worker {
                            let _ = worker.join();
                        }
                    }
                }
            }

            #[test]
            fn shutdown_log_file_backpressure_preserves_flood_past_both_queue_limits() {
                // Hold the worker in its first write so each bound is reached
                // deterministically, independent of filesystem or CPU speed.
                for line_bytes in [8, MAX_MESSAGE_BYTES] {
                    let mut fixture = Fixture::with_policy(None, true, MAX_MESSAGES, true);
                    fixture.block();
                    let mut line = vec![b'x'; line_bytes];
                    *line.last_mut().unwrap() = b'\n';
                    let capacity = MAX_MESSAGES.min(MAX_BYTES / line_bytes);
                    for _ in 0..capacity {
                        fixture.writer.write_all(&line).unwrap();
                    }
                    let (started, starting) = mpsc::channel();
                    let (done, completed) = mpsc::channel();
                    let mut writer = fixture.writer.clone();
                    let extra = line.clone();
                    let producer = thread::spawn(move || {
                        started.send(()).unwrap();
                        let result = writer.write_all(&extra);
                        done.send(result).unwrap();
                    });
                    starting.recv_timeout(BOUND).unwrap();
                    let blocked = completed.recv_timeout(Duration::from_millis(50));
                    fixture.release.send(()).unwrap();
                    producer.join().unwrap();
                    assert!(matches!(blocked, Err(mpsc::RecvTimeoutError::Timeout)));
                    completed.recv_timeout(BOUND).unwrap().unwrap();
                    fixture.writer.flush().unwrap();
                    let mut expected = b"first".to_vec();
                    expected.extend(line.repeat(capacity + 1));
                    assert_eq!(*fixture.bytes.lock().unwrap(), expected);
                }
            }

            #[test]
            fn shutdown_log_file_terminal_barrier_wakes_a_blocked_producer() {
                let mut fixture = Fixture::with_policy(None, true, 1, true);
                fixture.block();
                fixture.writer.write_all(b"accepted").unwrap();
                let (done, completed) = mpsc::channel();
                let mut writer = fixture.writer.clone();
                let producer = thread::spawn(move || {
                    done.send(writer.write_all(b"not admitted")).unwrap();
                });
                assert!(matches!(
                    completed.recv_timeout(Duration::from_millis(50)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                let ack = fixture.writer.request(Instant::now() + BOUND, true);
                assert_eq!(
                    completed.recv_timeout(BOUND).unwrap().unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                fixture.release.send(()).unwrap();
                producer.join().unwrap();
                wait_ack(&ack, Instant::now() + BOUND).unwrap();
                assert_eq!(*fixture.bytes.lock().unwrap(), b"firstaccepted");
            }

            #[test]
            fn shutdown_log_stdout_flood_reports_exact_line_counts_without_a_barrier() {
                for line_bytes in [8, MAX_MESSAGE_BYTES] {
                    let mut fixture = Fixture::new(None, true, MAX_MESSAGES);
                    fixture.block();
                    let mut line = vec![b'x'; line_bytes];
                    *line.last_mut().unwrap() = b'\n';
                    let capacity = MAX_MESSAGES.min(MAX_BYTES / line_bytes);
                    for _ in 0..capacity {
                        fixture.writer.write_all(&line).unwrap();
                    }
                    for _ in 0..37 {
                        assert_eq!(
                            fixture
                                .writer
                                .write_all(b"lost one\nlost two\n")
                                .unwrap_err()
                                .kind(),
                            io::ErrorKind::WouldBlock
                        );
                    }
                    // The per-event limit also counts all lines in the event.
                    let oversized = vec![b'\n'; MAX_MESSAGE_BYTES + 1];
                    assert_eq!(
                        fixture.writer.write_all(&oversized).unwrap_err().kind(),
                        io::ErrorKind::WouldBlock
                    );
                    let marker = format!("{} log lines dropped\n", 74 + oversized.len());
                    fixture.release.send(()).unwrap();
                    let deadline = Instant::now() + BOUND;
                    while !fixture.bytes.lock().unwrap().ends_with(marker.as_bytes()) {
                        assert!(
                            Instant::now() < deadline,
                            "loss marker was not written while idle"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    let mut expected = b"first".to_vec();
                    expected.extend(line.repeat(capacity));
                    expected.extend(marker.as_bytes());
                    assert_eq!(*fixture.bytes.lock().unwrap(), expected);
                    assert_eq!(
                        fixture.writer.flush().unwrap_err().kind(),
                        io::ErrorKind::WouldBlock
                    );
                    fixture.writer.flush().unwrap();
                    assert_eq!(
                        *fixture.bytes.lock().unwrap(),
                        expected,
                        "marker must appear exactly once"
                    );
                }
            }

            #[cfg(unix)]
            #[test]
            fn shutdown_log_file_receives_every_line_beyond_the_old_limits() {
                let root = directory_fixture();
                let path = root.path().join("flood.log");
                let (mut writer, _guard) = acknowledged_file(
                    File::create(&path).unwrap(),
                    Some(File::open(root.path()).unwrap()),
                )
                .unwrap();
                let mut expected = Vec::<u8>::new();
                for index in 0..4096 {
                    let line = format!("line {index:04}: {}\n", "x".repeat(1200));
                    writer.write_all(line.as_bytes()).unwrap();
                    expected.extend(line.as_bytes());
                }
                // A single large event is admitted intact, never split between
                // concurrent producers or rejected by the stdout size cap.
                let large = format!("{}\n", "y".repeat(MAX_BYTES + 1));
                writer.write_all(large.as_bytes()).unwrap();
                expected.extend(large.as_bytes());
                writer.flush().unwrap();
                assert_eq!(std::fs::read(path).unwrap(), expected);
            }

            #[test]
            fn shutdown_log_flush_limits_write_and_flush_failures_to_one_transaction() {
                for failure in [false, true] {
                    let mut fixture = Fixture::new(Some(failure), false, 8);
                    fixture.writer.write_all(b"first").unwrap();
                    assert!(fixture.writer.flush().is_err());
                    fixture.writer.write_all(b"healthy tail").unwrap();
                    fixture.writer.flush().unwrap();
                    assert!(fixture.bytes.lock().unwrap().ends_with(b"healthy tail"));
                }
            }

            fn captured(fixture: &Fixture) -> FlushCallback {
                use tracing_subscriber::layer::SubscriberExt;
                let dispatch = tracing::Dispatch::new(
                    tracing_subscriber::registry()
                        .with(FlushLayer::new(vec![fixture.writer.clone()]).unwrap()),
                );
                capture(&dispatch).unwrap()
            }

            #[test]
            fn shutdown_log_flush_barrier_keeps_admission_open_for_rollback() {
                let mut fixture = Fixture::new(None, true, 1);
                let callback = captured(&fixture);
                fixture.block();
                fixture.writer.write_all(b"second").unwrap();
                let deadline = Instant::now() + BOUND;
                // Upgrade barriers need their own slot even when writes fill the queue.
                let mut receivers = callback(deadline);
                let receiver = receivers.pop().unwrap();
                assert!(matches!(
                    receiver.recv_timeout(Duration::from_millis(50)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                fixture.release.send(()).unwrap();
                wait_ack(&receiver, deadline).unwrap();
                fixture.writer.write_all(b"after rollback").unwrap();
                flush_captured(&callback, Instant::now() + BOUND).unwrap();
                assert_eq!(*fixture.bytes.lock().unwrap(), b"firstsecondafter rollback");
            }

            #[test]
            fn shutdown_log_flush_dropped_line_fails_only_the_current_transaction() {
                let mut fixture = Fixture::new(None, true, 1);
                let callback = captured(&fixture);
                fixture.block();
                fixture.writer.write_all(b"accepted").unwrap();
                assert_eq!(
                    fixture.writer.write_all(b"dropped").unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                let deadline = Instant::now() + BOUND;
                let mut receivers = callback(deadline);
                fixture.release.send(()).unwrap();
                assert_eq!(
                    wait_ack(&receivers.pop().unwrap(), deadline)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                fixture.writer.write_all(b"healthy tail").unwrap();
                flush_captured(&callback, Instant::now() + BOUND).unwrap();
                assert_eq!(
                    *fixture.bytes.lock().unwrap(),
                    b"firstaccepted1 log lines dropped\nhealthy tail"
                );
            }

            #[test]
            fn shutdown_log_flush_loss_after_a_queued_barrier_belongs_to_the_next_window() {
                let mut fixture = Fixture::new(None, true, 1);
                let callback = captured(&fixture);
                fixture.block();
                fixture.writer.write_all(b"accepted").unwrap();
                let deadline = Instant::now() + BOUND;
                let mut receivers = callback(deadline);
                assert_eq!(
                    fixture.writer.write_all(b"later drop").unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                fixture.release.send(()).unwrap();
                wait_ack(&receivers.pop().unwrap(), deadline).unwrap();
                assert_eq!(
                    flush_captured(&callback, Instant::now() + BOUND)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                fixture.writer.write_all(b"healthy tail").unwrap();
                flush_captured(&callback, Instant::now() + BOUND).unwrap();
                assert_eq!(
                    *fixture.bytes.lock().unwrap(),
                    b"firstaccepted1 log lines dropped\nhealthy tail"
                );
            }

            #[test]
            fn shutdown_log_flush_hook_timeout_allows_later_writes_and_barriers() {
                let mut fixture = Fixture::new(None, true, 8);
                let callback = captured(&fixture);
                fixture.block();
                assert_eq!(
                    flush_captured(&callback, Instant::now() + Duration::from_millis(50))
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::TimedOut
                );
                // Admission must resume while the timed-out worker is still blocked.
                let admitted = fixture.writer.write_all(b"after timeout");
                fixture.release.send(()).unwrap();
                admitted.unwrap();
                flush_captured(&callback, Instant::now() + BOUND).unwrap();
                assert_eq!(*fixture.bytes.lock().unwrap(), b"firstafter timeout");
            }

            #[test]
            fn shutdown_log_flush_waits_for_queued_writes_and_closes_admission() {
                let mut fixture = Fixture::new(None, true, 1);
                fixture.block();
                fixture.writer.write_all(b"second").unwrap();
                let deadline = Instant::now() + BOUND;
                // The terminal barrier must fit even when the write queue is full.
                let ack = fixture.writer.request(deadline, true);
                assert!(matches!(
                    ack.recv_timeout(Duration::from_millis(50)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                assert!(fixture.writer.write_all(b"too late").is_err());
                fixture.release.send(()).unwrap();
                fixture.writer.wait(&ack, deadline).unwrap();
                assert_eq!(*fixture.bytes.lock().unwrap(), b"firstsecond");
            }

            fn assert_overflow_fails_one_transaction(
                capacity: usize,
                chunks: usize,
                chunk_size: usize,
                rejected_size: usize,
            ) {
                let mut fixture = Fixture::new(None, true, capacity);
                fixture.block();
                for _ in 0..chunks {
                    fixture.writer.write_all(&vec![0; chunk_size]).unwrap();
                }
                assert_eq!(
                    fixture
                        .writer
                        .write(&vec![0; rejected_size])
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
                fixture.release.send(()).unwrap();
                assert_eq!(
                    fixture.writer.flush().unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                let mut expected = b"first".to_vec();
                expected.extend(vec![0; chunks * chunk_size]);
                // The rejected write is one unterminated line. Main's bounded
                // stdout sink reports that loss before the failed barrier.
                expected.extend_from_slice(b"1 log lines dropped\n");
                assert_eq!(*fixture.bytes.lock().unwrap(), expected);
                fixture.writer.write_all(b"healthy tail").unwrap();
                fixture.writer.flush().unwrap();
                expected.extend_from_slice(b"healthy tail");
                assert_eq!(*fixture.bytes.lock().unwrap(), expected);
            }

            #[test]
            fn shutdown_log_flush_message_overflow_fails_one_transaction() {
                assert_overflow_fails_one_transaction(1, 1, 1, 1);
            }

            #[test]
            fn shutdown_log_flush_byte_overflow_fails_one_transaction() {
                assert_overflow_fails_one_transaction(
                    MAX_MESSAGES,
                    MAX_BYTES / MAX_MESSAGE_BYTES,
                    MAX_MESSAGE_BYTES,
                    1,
                );
            }

            #[test]
            fn shutdown_log_flush_oversized_message_fails_one_transaction() {
                assert_overflow_fails_one_transaction(MAX_MESSAGES, 0, 0, MAX_MESSAGE_BYTES + 1);
            }

            #[test]
            fn shutdown_log_flush_hang_cannot_extend_its_deadline() {
                let mut fixture = Fixture::new(None, true, 8);
                fixture.block();
                let deadline = Instant::now() + Duration::from_millis(50);
                assert_eq!(
                    fixture.writer.flush_until(deadline).unwrap_err().kind(),
                    io::ErrorKind::TimedOut
                );
                let retry = Instant::now();
                assert!(fixture.writer.flush_until(retry + BOUND).is_err());
                assert!(retry.elapsed() < Duration::from_millis(500));
                assert!(fixture.bytes.lock().unwrap().is_empty());
                fixture.release.send(()).unwrap();
            }

            #[test]
            fn shutdown_log_flush_refuses_a_failed_durability_barrier() {
                let (mut writer, mut guard) = start(
                    std::io::sink(),
                    |_| Err(io::Error::other("injected durability barrier failure")),
                    8,
                    false,
                )
                .unwrap();
                writer.write_all(b"accepted bytes").unwrap();
                assert_eq!(
                    guard
                        .shutdown_until(Instant::now() + BOUND)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::Other
                );
            }

            #[cfg(unix)]
            fn directory_fixture() -> tempfile::TempDir {
                let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("target/upgrade-log-directory-tests");
                std::fs::create_dir_all(&root).unwrap();
                tempfile::tempdir_in(root).unwrap()
            }

            #[cfg(unix)]
            #[test]
            fn shutdown_log_directory_existing_folders_are_not_synced() {
                let root = directory_fixture();
                let existing = root.path().join("existing");
                std::fs::create_dir(&existing).unwrap();
                let mut synced = Vec::new();
                prepare_log_dir(
                    &existing,
                    |path| {
                        synced.push(path.to_path_buf());
                        Ok(())
                    },
                    |_, error| panic!("unexpected directory warning: {error}"),
                )
                .unwrap();
                assert!(synced.is_empty());
            }

            #[cfg(unix)]
            #[test]
            fn shutdown_log_directory_syncs_only_folders_it_created() {
                let root = directory_fixture();
                let nested = root.path().join("new/deep");
                let mut synced = Vec::new();
                prepare_log_dir(
                    &nested,
                    |path| {
                        synced.push(path.to_path_buf());
                        File::open(path)?.sync_all()
                    },
                    |_, error| panic!("unexpected directory warning: {error}"),
                )
                .unwrap();
                assert_eq!(synced, vec![nested.clone(), root.path().join("new")]);
                assert!(nested.is_dir());
            }

            #[cfg(unix)]
            #[test]
            fn shutdown_log_directory_unreadable_folder_only_warns() {
                let root = directory_fixture();
                let nested = root.path().join("new/deep");
                let mut warnings = Vec::new();
                prepare_log_dir(
                    &nested,
                    |_| {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "unreadable folder",
                        ))
                    },
                    |path, error| warnings.push((path.to_path_buf(), error.kind())),
                )
                .unwrap();
                assert_eq!(
                    warnings,
                    vec![
                        (nested.clone(), io::ErrorKind::PermissionDenied),
                        (root.path().join("new"), io::ErrorKind::PermissionDenied),
                    ]
                );
                let path = nested.join("daemon.log");
                let file = File::create(&path).unwrap();
                // Directory access was unavailable; the file remains writable and flushable.
                let (mut writer, _guard) = acknowledged_file(file, None).unwrap();
                writer
                    .write_all(b"file logging survives directory warning")
                    .unwrap();
                writer.flush().unwrap();
                assert_eq!(
                    std::fs::read(path).unwrap(),
                    b"file logging survives directory warning"
                );
            }

            #[test]
            fn shutdown_log_flush_retains_an_unrecovered_sink_setup_failure() {
                let mut fixture = Fixture::new(None, false, 8);
                fixture.writer.record_setup_error(&io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "configured sink did not open",
                ));
                for _ in 0..2 {
                    fixture.writer.write_all(b"stdout still works").unwrap();
                    assert_eq!(
                        fixture.writer.flush().unwrap_err().kind(),
                        io::ErrorKind::PermissionDenied
                    );
                }
                assert_eq!(
                    *fixture.bytes.lock().unwrap(),
                    b"stdout still worksstdout still works"
                );
            }

            #[test]
            fn shutdown_log_flush_uses_the_owning_dispatch_bridge() {
                use tracing_subscriber::layer::SubscriberExt;
                let mut fixture = Fixture::new(None, false, 8);
                let dispatch = tracing::Dispatch::new(
                    tracing_subscriber::registry()
                        .with(FlushLayer::new(vec![fixture.writer.clone()]).unwrap()),
                );
                fixture.writer.write_all(b"captured sink").unwrap();
                flush_captured(&capture(&dispatch).unwrap(), Instant::now() + BOUND).unwrap();
                assert_eq!(*fixture.bytes.lock().unwrap(), b"captured sink");
                assert!(capture(&tracing::Dispatch::new(tracing_subscriber::registry())).is_err());
            }
        }
    };
}
