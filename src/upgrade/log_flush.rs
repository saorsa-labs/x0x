//! Owned log sinks with acknowledged transaction barriers.
//! Files apply back-pressure; bounded stdout reports dropped lines.
//! The transaction checks its suspend-inclusive deadline around this local wait.
//! Transaction barriers leave admission open for rollback. Only guard teardown
//! closes admission and terminates the worker.
#![allow(dead_code)] // Shared privately by the daemon binary and the library.

use std::any::TypeId;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
#[cfg(unix)]
use std::path::Path;
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
    Flush {
        deadline: Instant,
        ack: mpsc::Sender<io::Result<()>>,
        terminal: bool,
        admission_failure: Option<(io::ErrorKind, &'static str)>,
    },
}

struct State {
    // Each entry carries the losses that precede it, including flush markers.
    queue: VecDeque<(Message, usize)>,
    bytes: usize,
    dropped_lines: usize,
    failure: Option<(io::ErrorKind, &'static str)>,
    setup_failure: Option<(io::ErrorKind, &'static str)>,
    deadline: Option<Instant>,
    closed: bool,
    alive: bool,
}

struct Shared {
    state: Mutex<State>,
    ready: Condvar,
    space: Condvar,
    capacity: usize,
    lossless: bool,
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
    start(sink, Write::flush, MAX_MESSAGES, false)
}

#[cfg(test)]
pub(crate) fn acknowledged_with_capacity<W: Write + Send + 'static>(
    sink: W,
    capacity: usize,
) -> io::Result<(LogWriter, LogGuard)> {
    start(sink, Write::flush, capacity, false)
}

fn start<W, F>(
    sink: W,
    barrier: F,
    capacity: usize,
    lossless: bool,
) -> io::Result<(LogWriter, LogGuard)>
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
            dropped_lines: 0,
            failure: None,
            setup_failure: None,
            deadline: None,
            closed: false,
            alive: true,
        }),
        ready: Condvar::new(),
        space: Condvar::new(),
        capacity,
        lossless,
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
        if let Ok(mut state) = self.shared.state.lock() {
            // The configured sink never started, so later barriers cannot
            // recover it. Directory-access warnings do not take this path.
            state
                .setup_failure
                .get_or_insert((error.kind(), "configured log sink setup failed"));
        }
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
            // Reserve a control slot even when writes fill the queue. Further
            // callers fail their own request without poisoning a later barrier.
            if !terminal && state.queue.len() > self.shared.capacity {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "logging queue is full",
                ));
            }
            state.closed = terminal;
            // Errors after this marker belong to the next transaction. Sink
            // errors are ordered by the worker's own position in the queue.
            let admission_failure = state.setup_failure.or(state.failure.take());
            let dropped_lines = std::mem::take(&mut state.dropped_lines);
            state.queue.push_back((
                Message::Flush {
                    deadline,
                    ack: ack.clone(),
                    terminal,
                    admission_failure,
                },
                dropped_lines,
            ));
            if terminal {
                self.shared.space.notify_all();
            }
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
        // A timed-out non-terminal request must not constrain future requests.
        // The queued marker consumes its own error window when the sink resumes.
        wait_ack(ack, deadline)
    }
}

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut state = self.shared.state.lock().map_err(|_| poisoned())?;
        loop {
            if !state.alive || state.closed {
                return Err(unavailable());
            }
            // Keep each file event intact. One event larger than the byte
            // budget may enter an otherwise byte-empty queue; subsequent
            // writes wait for space. Stdout retains its per-event cap.
            if (self.shared.lossless || bytes.len() <= MAX_MESSAGE_BYTES)
                && state.queue.len() < self.shared.capacity
                && (bytes.len() <= MAX_BYTES.saturating_sub(state.bytes)
                    || (self.shared.lossless && state.bytes == 0))
            {
                break;
            }
            if self.shared.lossless {
                state = self.shared.space.wait(state).map_err(|_| poisoned())?;
                continue;
            }
            // tracing submits a formatted event in one write_all. Count its
            // lines, including a final line without a newline.
            state.dropped_lines += bytes.iter().filter(|&&byte| byte == b'\n').count()
                + usize::from(!bytes.ends_with(b"\n"));
            state
                .failure
                .get_or_insert((io::ErrorKind::WouldBlock, "logging queue lost a write"));
            self.shared.ready.notify_one();
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "logging queue capacity exceeded",
            ));
        }
        state.bytes += bytes.len();
        let dropped_lines = std::mem::take(&mut state.dropped_lines);
        state
            .queue
            .push_back((Message::Write(bytes.to_vec()), dropped_lines));
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
        self.0.space.notify_all();
    }
}

fn run<W: Write, F: FnMut(&mut W) -> io::Result<()>>(mut sink: W, mut barrier: F, shared: &Shared) {
    let mut sink_failure = None;
    loop {
        let (message, dropped_lines) = {
            let Ok(mut state) = shared.state.lock() else {
                return;
            };
            while state.queue.is_empty() && state.dropped_lines == 0 {
                let Ok(next) = shared.ready.wait(state) else {
                    return;
                };
                state = next;
            }
            // Report overflow even if no further writes or barriers arrive.
            let (message, dropped_lines) = state.queue.pop_front().unwrap_or_else(|| {
                (
                    Message::Write(Vec::new()),
                    std::mem::take(&mut state.dropped_lines),
                )
            });
            if let Message::Write(bytes) = &message {
                state.bytes = state.bytes.saturating_sub(bytes.len());
            }
            shared.space.notify_all();
            (message, dropped_lines)
        };
        if dropped_lines != 0 {
            if let Err(error) = writeln!(sink, "{dropped_lines} log lines dropped") {
                sink_failure.get_or_insert((error.kind(), "log loss marker write failed"));
            }
        }
        match message {
            Message::Write(bytes) => {
                if let Err(error) = sink.write_all(&bytes) {
                    sink_failure.get_or_insert((error.kind(), "log sink write failed"));
                }
                if let Err(error) = sink.flush() {
                    sink_failure.get_or_insert((error.kind(), "log sink flush failed"));
                }
            }
            Message::Flush {
                deadline,
                ack,
                terminal,
                admission_failure,
            } => {
                // Consume this window even if its deadline or barrier fails.
                // A later transaction can succeed after the sink recovers.
                let failure = admission_failure.or(sink_failure.take());
                let result = (|| {
                    if Instant::now() >= deadline {
                        return Err(timed_out());
                    }
                    barrier(&mut sink)?;
                    let state = shared.state.lock().map_err(|_| poisoned())?;
                    let deadline = state.deadline.map_or(deadline, |prior| prior.min(deadline));
                    if Instant::now() >= deadline {
                        return Err(timed_out());
                    }
                    failure.map_or(Ok(()), |(kind, message)| Err(io::Error::new(kind, message)))
                })();
                let _ = ack.send(result);
                if terminal {
                    return;
                }
            }
        }
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
    parent: Option<File>,
}

// An unavailable directory handle is warned about at setup. It must not disable
// file logging or block upgrades; the file still receives its durability barrier.
pub(crate) fn acknowledged_file(
    file: File,
    parent: Option<File>,
) -> io::Result<(LogWriter, LogGuard)> {
    if !file.metadata()?.is_file()
        || parent
            .as_ref()
            .map(File::metadata)
            .transpose()?
            .is_some_and(|meta| !meta.is_dir())
    {
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
            sink.parent.as_ref().map_or(Ok(()), File::sync_all)
        },
        MAX_MESSAGES,
        true,
    )
}

/// Create the log directory and sync only the directories this call creates.
/// Directory barriers are best effort at startup. The file barrier remains strict.
#[cfg(unix)]
pub(crate) fn prepare_log_dir(
    dir: &Path,
    mut sync: impl FnMut(&Path) -> io::Result<()>,
    mut warn: impl FnMut(&Path, &io::Error),
) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut parent = dir;
    loop {
        match std::fs::metadata(parent) {
            Ok(meta) if meta.is_dir() => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "log parent is not a directory",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(parent.to_path_buf());
                parent = parent
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
            }
            Err(error) => return Err(error),
        }
    }
    let mut created = Vec::new();
    for path in missing.iter().rev() {
        match std::fs::create_dir(path) {
            Ok(()) => created.push(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
            Err(error) => return Err(error),
        }
    }
    for path in created.into_iter().rev() {
        if let Err(error) = sync(path) {
            warn(path, &error);
        }
    }
    Ok(())
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
                    // Receipt publication can still fail after this barrier.
                    // Keep admission open until the daemon actually exits.
                    .map(|writer| writer.request(deadline, false))
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

/// Drain failure diagnostics before process::exit skips the worker guard.
/// This has a fresh, short budget because the upgrade deadline may have passed.
pub(crate) fn flush_before_exit(captured: Option<&FlushCallback>) {
    let current;
    let callback = match captured {
        Some(callback) => callback,
        None => {
            current = capture(&tracing::dispatcher::get_default(Clone::clone));
            match &current {
                Ok(callback) => callback,
                Err(error) => {
                    eprintln!("cannot flush upgrade failure logs before exit: {error}");
                    return;
                }
            }
        }
    };
    if let Err(error) = flush_captured(callback, Instant::now() + Duration::from_secs(1)) {
        eprintln!("cannot flush upgrade failure logs before exit: {error}");
    }
}

#[cfg(test)]
include!("../../tests/upgrade_log_flush.rs");
#[cfg(test)]
log_flush_regression_tests!();
