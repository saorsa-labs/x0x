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
                    let bytes = Arc::new(Mutex::new(Vec::new()));
                    let (release, released) = mpsc::channel();
                    let (entered, entered_rx) = mpsc::channel();
                    let sink = Sink {
                        bytes: bytes.clone(),
                        failure,
                        blocked: block.then_some((entered, released)),
                    };
                    let (writer, guard) = acknowledged_with_capacity(sink, capacity).unwrap();
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
                assert_eq!(*fixture.bytes.lock().unwrap(), b"firstacceptedhealthy tail");
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
                assert_eq!(*fixture.bytes.lock().unwrap(), b"firstacceptedhealthy tail");
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
