//! Owned, nonblocking log sinks with a terminal acknowledged drain.
//! The transaction checks its suspend-inclusive deadline around this local wait.
#![allow(dead_code)] // Shared privately by the daemon binary and the library.

use std::any::TypeId;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const ACK_LIMIT: Duration = Duration::from_secs(30);
const MAX_MESSAGES: usize = 1024;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

// Standard-library types preserve TypeId across the private binary/lib copies.
pub(crate) type FlushCallback =
    Arc<dyn Fn(Instant) -> Vec<mpsc::Receiver<io::Result<()>>> + Send + Sync>;

enum Message {
    Write(Vec<u8>),
    Flush(Instant, mpsc::Sender<io::Result<()>>, bool),
}

struct State {
    queue: VecDeque<Message>,
    bytes: usize,
    failure: Option<(io::ErrorKind, &'static str)>,
    deadline: Option<Instant>,
    closed: bool,
    alive: bool,
}

struct Shared {
    state: Mutex<State>,
    ready: Condvar,
    capacity: usize,
}

#[derive(Clone)]
pub(crate) struct LogWriter {
    shared: Arc<Shared>,
}

pub(crate) struct LogGuard {
    writer: LogWriter,
    worker: Option<JoinHandle<()>>,
}

pub(crate) fn acknowledged<W: Write + Send + 'static>(
    sink: W,
) -> io::Result<(LogWriter, LogGuard)> {
    start(sink, Write::flush, MAX_MESSAGES)
}

#[cfg(test)]
pub(crate) fn acknowledged_with_capacity<W: Write + Send + 'static>(
    sink: W,
    capacity: usize,
) -> io::Result<(LogWriter, LogGuard)> {
    start(sink, Write::flush, capacity)
}

fn start<W, F>(sink: W, barrier: F, capacity: usize) -> io::Result<(LogWriter, LogGuard)>
where
    W: Write + Send + 'static,
    F: FnMut(&mut W) -> io::Result<()> + Send + 'static,
{
    if capacity == 0 || capacity > MAX_MESSAGES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid logging queue capacity",
        ));
    }
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            queue: VecDeque::new(),
            bytes: 0,
            failure: None,
            deadline: None,
            closed: false,
            alive: true,
        }),
        ready: Condvar::new(),
        capacity,
    });
    let worker_state = Arc::clone(&shared);
    let worker = thread::Builder::new()
        .name("x0x-log-writer".into())
        .spawn(move || {
            let _exit = WorkerExit(Arc::clone(&worker_state));
            run(sink, barrier, &worker_state);
        })?;
    let writer = LogWriter { shared };
    Ok((
        writer.clone(),
        LogGuard {
            writer,
            worker: Some(worker),
        },
    ))
}

impl LogWriter {
    pub(crate) fn record_setup_error(&self, error: &io::Error) {
        remember(
            &self.shared,
            error.kind(),
            "configured log sink setup failed",
        );
    }

    pub(crate) fn flush_until(&self, deadline: Instant) -> io::Result<()> {
        let deadline = deadline.min(next_deadline());
        let ack = self.request(deadline, true);
        self.wait(&ack, deadline)
    }

    fn request(&self, deadline: Instant, terminal: bool) -> mpsc::Receiver<io::Result<()>> {
        let (ack, receiver) = mpsc::channel();
        let result = (|| {
            let mut state = self.shared.state.lock().map_err(|_| poisoned())?;
            let deadline = state.deadline.map_or(deadline, |prior| prior.min(deadline));
            if terminal {
                state.deadline = Some(deadline);
            }
            if !state.alive || state.closed {
                return Err(unavailable());
            }
            // The terminal control slot is reserved even when writes fill the queue.
            if !terminal && state.queue.len() >= self.shared.capacity {
                state
                    .failure
                    .get_or_insert((io::ErrorKind::WouldBlock, "logging queue lost a barrier"));
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "logging queue is full",
                ));
            }
            state.closed = terminal;
            state
                .queue
                .push_back(Message::Flush(deadline, ack.clone(), terminal));
            self.shared.ready.notify_one();
            Ok(())
        })();
        if let Err(error) = result {
            let _ = ack.send(Err(error));
        }
        receiver
    }

    fn wait(&self, ack: &mpsc::Receiver<io::Result<()>>, deadline: Instant) -> io::Result<()> {
        let deadline = self
            .shared
            .state
            .lock()
            .map_err(|_| poisoned())?
            .deadline
            .map_or(deadline, |prior| prior.min(deadline));
        let result = wait_ack(ack, deadline);
        if let Err(error) = &result {
            let mut state = self.shared.state.lock().map_err(|_| poisoned())?;
            state
                .failure
                .get_or_insert((error.kind(), "logging flush was not acknowledged"));
            state.deadline = Some(deadline);
        }
        result
    }
}

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut state = self.shared.state.lock().map_err(|_| poisoned())?;
        if !state.alive || state.closed {
            return Err(unavailable());
        }
        if bytes.len() > MAX_MESSAGE_BYTES
            || state.queue.len() >= self.shared.capacity
            || bytes.len() > MAX_BYTES.saturating_sub(state.bytes)
        {
            state
                .failure
                .get_or_insert((io::ErrorKind::WouldBlock, "logging queue lost a write"));
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "logging queue capacity exceeded",
            ));
        }
        state.bytes += bytes.len();
        state.queue.push_back(Message::Write(bytes.to_vec()));
        self.shared.ready.notify_one();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let deadline = next_deadline();
        let ack = self.request(deadline, false);
        self.wait(&ack, deadline)
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogGuard {
    pub(crate) fn shutdown_until(&mut self, deadline: Instant) -> io::Result<()> {
        let result = self.writer.flush_until(deadline);
        // Never join a blocked sink. A timeout retains its sink in the worker.
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished)
            && self
                .worker
                .take()
                .is_some_and(|worker| worker.join().is_err())
        {
            return Err(unavailable());
        }
        result
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        // flush_until reuses the earliest deadline, including after timeout.
        let _ = self.shutdown_until(next_deadline());
    }
}

struct WorkerExit(Arc<Shared>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.alive = false;
        state.closed = true;
        state.queue.clear(); // Pending receivers disconnect, never acknowledge.
    }
}

fn run<W: Write, F: FnMut(&mut W) -> io::Result<()>>(mut sink: W, mut barrier: F, shared: &Shared) {
    loop {
        let message = {
            let Ok(mut state) = shared.state.lock() else {
                return;
            };
            while state.queue.is_empty() {
                let Ok(next) = shared.ready.wait(state) else {
                    return;
                };
                state = next;
            }
            let Some(message) = state.queue.pop_front() else {
                return;
            };
            if let Message::Write(bytes) = &message {
                state.bytes = state.bytes.saturating_sub(bytes.len());
            }
            message
        };
        match message {
            Message::Write(bytes) => {
                if let Err(error) = sink.write_all(&bytes) {
                    remember(shared, error.kind(), "log sink write failed");
                }
                if let Err(error) = sink.flush() {
                    remember(shared, error.kind(), "log sink flush failed");
                }
            }
            Message::Flush(deadline, ack, terminal) => {
                let result = (|| {
                    if Instant::now() >= deadline {
                        return Err(timed_out());
                    }
                    if let Err(error) = barrier(&mut sink) {
                        remember(shared, error.kind(), "log sink barrier failed");
                    }
                    let state = shared.state.lock().map_err(|_| poisoned())?;
                    let deadline = state.deadline.map_or(deadline, |prior| prior.min(deadline));
                    if Instant::now() >= deadline {
                        return Err(timed_out());
                    }
                    state
                        .failure
                        .map_or(Ok(()), |(kind, message)| Err(io::Error::new(kind, message)))
                })();
                let _ = ack.send(result);
                if terminal {
                    return;
                }
            }
        }
    }
}

fn remember(shared: &Shared, kind: io::ErrorKind, message: &'static str) {
    if let Ok(mut state) = shared.state.lock() {
        state.failure.get_or_insert((kind, message));
    }
}

fn next_deadline() -> Instant {
    let now = Instant::now();
    now.checked_add(ACK_LIMIT).unwrap_or(now)
}

fn wait_ack(ack: &mpsc::Receiver<io::Result<()>>, deadline: Instant) -> io::Result<()> {
    let now = Instant::now();
    if now >= deadline {
        return Err(timed_out());
    }
    let result = match ack.recv_timeout(deadline.saturating_duration_since(now)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(timed_out()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(unavailable()),
    };
    if Instant::now() >= deadline {
        Err(timed_out())
    } else {
        result
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "logging flush exceeded its deadline",
    )
}
fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "logging worker is unavailable")
}
fn poisoned() -> io::Error {
    io::Error::other("logging state is poisoned")
}

struct FileSink {
    file: File,
    parent: File,
}

// Setup must separately make newly created ancestor directories durable.
pub(crate) fn acknowledged_file(file: File, parent: File) -> io::Result<(LogWriter, LogGuard)> {
    if !file.metadata()?.is_file() || !parent.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid log barrier handles",
        ));
    }
    start(
        FileSink { file, parent },
        |sink| {
            sink.file.flush()?;
            sink.file.sync_all()?;
            sink.parent.sync_all()
        },
        MAX_MESSAGES,
    )
}
impl Write for FileSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

pub(crate) fn capture(dispatch: &tracing::Dispatch) -> io::Result<FlushCallback> {
    dispatch
        .downcast_ref::<FlushCallback>()
        .cloned()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "daemon logger has no acknowledged flush bridge",
            )
        })
}

pub(crate) struct FlushLayer {
    callback: FlushCallback,
}
impl FlushLayer {
    pub(crate) fn new(writers: Vec<LogWriter>) -> io::Result<Self> {
        if writers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "flush bridge has no log sinks",
            ));
        }
        Ok(Self {
            callback: Arc::new(move |deadline| {
                let deadline = deadline.min(next_deadline());
                writers
                    .iter()
                    .map(|writer| writer.request(deadline, true))
                    .collect()
            }),
        })
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for FlushLayer {
    unsafe fn downcast_raw(&self, id: TypeId) -> Option<*const ()> {
        // SAFETY: each live field pointer is returned only for its exact TypeId.
        if id == TypeId::of::<Self>() {
            Some(std::ptr::from_ref(self).cast())
        } else if id == TypeId::of::<FlushCallback>() {
            Some(std::ptr::from_ref(&self.callback).cast())
        } else {
            None
        }
    }
}

pub(crate) fn flush_captured(callback: &FlushCallback, deadline: Instant) -> io::Result<()> {
    let deadline = deadline.min(next_deadline());
    let receivers = callback(deadline);
    if receivers.is_empty() {
        return Err(unavailable());
    }
    let mut failure = None;
    for receiver in receivers {
        if let Err(error) = wait_ack(&receiver, deadline) {
            failure.get_or_insert(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
include!("../../tests/upgrade_log_flush.rs");
#[cfg(test)]
log_flush_regression_tests!();
