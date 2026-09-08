//! Disposable #574 observation only. Never used to decide readiness.
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use ant_quic::{PeerId, PeerLifecycleEvent};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

const ROW_LIMIT: usize = 256;
const EVENT_LIMIT: usize = 1024;
type Events = broadcast::Receiver<(PeerId, PeerLifecycleEvent)>;

#[derive(Debug, Clone, Copy)]
pub(super) enum Side {
    Owner,
    Joiner,
}

impl Side {
    fn index(self) -> usize {
        match self {
            Self::Owner => 0,
            Self::Joiner => 1,
        }
    }
}

#[derive(Debug)]
enum Observation {
    Lifecycle(PeerLifecycleEvent),
    Lagged(u64),
    StreamClosed,
    StreamUnavailable,
    CaptureLimit,
    CaptureDeadline,
    Snapshot(Option<(bool, bool)>),
    Publish(Option<u32>),
    Marker(&'static str),
}

#[derive(Debug)]
struct Row {
    sequence: u64,
    elapsed_us: u128,
    side: Side,
    observation: Observation,
}

#[derive(Debug, Default)]
struct State {
    rows: Vec<Row>,
    total: u64,
    overflow: u64,
    foreign: [u64; 2],
    lagged: [u64; 2],
    closed: [bool; 2],
    // Cancellation discards pending events: preserve that evidence gap.
    pending_at_stop: [usize; 2],
    collectors_dropped: [bool; 2],
}

struct Journal {
    started: Instant,
    state: Mutex<State>,
}

impl Journal {
    fn update(&self, f: impl FnOnce(&mut State)) {
        f(&mut self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
    }

    fn record(&self, side: Side, observation: Observation) {
        self.update(|state| {
            state.total = state.total.saturating_add(1);
            if state.rows.len() < ROW_LIMIT {
                state.rows.push(Row {
                    sequence: state.total,
                    elapsed_us: self.started.elapsed().as_micros(),
                    side,
                    observation,
                });
            } else {
                state.overflow = state.overflow.saturating_add(1);
            }
        });
    }
}

// Own the receiver inside the spawned future, including before its first poll.
// Dropping/aborting the task records unread events and receiver destruction.
struct Capture {
    receiver: Events,
    journal: Arc<Journal>,
    side: Side,
    counterpart: PeerId,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.journal.update(|state| {
            state.pending_at_stop[self.side.index()] = self.receiver.len();
            state.collectors_dropped[self.side.index()] = true;
        });
    }
}

impl Capture {
    async fn run(mut self) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        for _ in 0..EVENT_LIMIT {
            let received = match tokio::time::timeout_at(deadline, self.receiver.recv()).await {
                Ok(received) => received,
                Err(_) => {
                    self.journal.record(self.side, Observation::CaptureDeadline);
                    return;
                }
            };
            match received {
                Ok((peer, event)) if peer == self.counterpart => {
                    self.journal
                        .record(self.side, Observation::Lifecycle(event));
                }
                Ok(_) => self.journal.update(|state| {
                    let count = &mut state.foreign[self.side.index()];
                    *count = count.saturating_add(1);
                }),
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    self.journal.update(|state| {
                        let total = &mut state.lagged[self.side.index()];
                        *total = total.saturating_add(count);
                    });
                    self.journal.record(self.side, Observation::Lagged(count));
                }
                Err(broadcast::error::RecvError::Closed) => {
                    self.journal
                        .update(|state| state.closed[self.side.index()] = true);
                    self.journal.record(self.side, Observation::StreamClosed);
                    return;
                }
            }
        }
        self.journal.record(self.side, Observation::CaptureLimit);
    }
}

pub(super) struct Trace {
    journal: Arc<Journal>,
    tasks: Vec<JoinHandle<()>>,
    finished: bool,
}

impl Trace {
    pub(super) fn new() -> Self {
        Self {
            journal: Arc::new(Journal {
                started: Instant::now(),
                state: Mutex::default(),
            }),
            tasks: Vec::new(),
            finished: false,
        }
    }

    pub(super) fn attach(&mut self, side: Side, receiver: Option<Events>, counterpart: PeerId) {
        if let Some(receiver) = receiver {
            let capture = Capture {
                receiver,
                journal: Arc::clone(&self.journal),
                side,
                counterpart,
            };
            self.tasks.push(tokio::spawn(capture.run()));
        } else {
            self.journal.record(side, Observation::StreamUnavailable);
        }
    }

    pub(super) fn marker(&self, side: Side, marker: &'static str) {
        self.journal.record(side, Observation::Marker(marker));
    }

    /// A single poll only: a contended network lock produces UNKNOWN and the
    /// future is dropped immediately. No timer, sleep, task or retained waker.
    /// Transport and send-ready are sequential observations, NOT an atomic pair.
    pub(super) fn snapshot(&self, side: Side, future: impl Future<Output = (bool, bool)>) {
        let mut future = std::pin::pin!(future);
        let value = match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        };
        self.journal.record(side, Observation::Snapshot(value));
    }

    pub(super) fn published(&self, side: Side, fanout: Option<u32>) {
        self.journal.record(side, Observation::Publish(fanout));
    }

    pub(super) async fn finish(mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks.drain(..) {
            // Cancellation is expected; any panic is separately visible.
            if let Err(error) = task.await {
                if !error.is_cancelled() {
                    self.journal
                        .record(Side::Owner, Observation::Marker("collector_join_error"));
                }
            }
        }
        self.finished = true;
        self.emit("collectors_joined");
    }

    fn emit(&self, stop: &str) {
        self.journal.update(|state| {
            for row in &state.rows {
                // All fields are closed scalars/enums. No peer/address/payload
                // Debug formatting; ant-quic lifecycle variants contain only
                // generations and the closed ConnectionCloseReason enum.
                let detail = match &row.observation {
                    Observation::Lifecycle(event) => format!("lifecycle={event:?}"),
                    Observation::Lagged(count) => format!("lagged={count}"),
                    Observation::StreamClosed => "stream_closed".to_string(),
                    Observation::StreamUnavailable => "stream_unavailable".to_string(),
                    Observation::CaptureLimit => "capture_event_limit".to_string(),
                    Observation::CaptureDeadline => "capture_deadline".to_string(),
                    Observation::Snapshot(value) => format!("transport_send_ready={value:?} admission=unavailable"),
                    Observation::Publish(value) => format!("publish_attempted={value:?}"),
                    Observation::Marker(value) => format!("marker={value}"),
                };
                eprintln!("DIAG lifecycle574 seq={} elapsed_us={} side={:?} {}",
                    row.sequence, row.elapsed_us, row.side, detail);
            }
            eprintln!("DIAG lifecycle574 stop={stop} total={} overflow={} foreign={:?} lagged={:?} stream_closed={:?} pending_at_stop={:?} collectors_dropped={:?} acceptance=not_evaluated",
                state.total, state.overflow, state.foreign, state.lagged, state.closed,
                state.pending_at_stop, state.collectors_dropped);
        });
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if !self.finished {
            for task in &self.tasks {
                task.abort();
            }
            // Early fixture error/panic: abort requested, not falsely reaped.
            self.emit("abort_requested_on_drop");
        }
    }
}

#[tokio::test]
async fn lifecycle574_order_lag_foreign_and_closed_are_retained() {
    let (tx, rx) = broadcast::channel(4);
    let peer = PeerId([1; 32]);
    let other = PeerId([2; 32]);
    for generation in 0..6 {
        tx.send((peer, PeerLifecycleEvent::Established { generation }))
            .unwrap();
    }
    let mut trace = Trace::new();
    let journal = Arc::clone(&trace.journal);
    trace.attach(Side::Joiner, Some(rx), peer);
    // Wait for an observable receive result, not a scheduling guess.
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if journal.state.lock().unwrap().rows.len() == 5 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tx.send((other, PeerLifecycleEvent::ReaderExited { generation: 99 }))
        .unwrap();
    tx.send((
        peer,
        PeerLifecycleEvent::Replaced {
            old_generation: 5,
            new_generation: 6,
        },
    ))
    .unwrap();
    tx.send((
        peer,
        PeerLifecycleEvent::Closing {
            generation: 6,
            reason: ant_quic::ConnectionCloseReason::TimedOut,
        },
    ))
    .unwrap();
    tx.send((
        peer,
        PeerLifecycleEvent::Closed {
            generation: 6,
            reason: ant_quic::ConnectionCloseReason::TimedOut,
        },
    ))
    .unwrap();
    drop(tx);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if journal.state.lock().unwrap().collectors_dropped[1] {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    trace.finish().await;
    let state = journal.state.lock().unwrap();
    assert_eq!(state.lagged, [0, 2]);
    assert_eq!(state.foreign, [0, 1]);
    assert!(state.closed[1]);
    assert_eq!(state.pending_at_stop[1], 0);
    assert!(matches!(state.rows[0].observation, Observation::Lagged(2)));
    let events: Vec<_> = state
        .rows
        .iter()
        .filter_map(|row| match &row.observation {
            Observation::Lifecycle(event) => Some(event.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(events.len(), 7);
    assert_eq!(events[0], PeerLifecycleEvent::Established { generation: 2 });
    assert_eq!(
        events[4],
        PeerLifecycleEvent::Replaced {
            old_generation: 5,
            new_generation: 6
        }
    );
    assert_eq!(
        events[5],
        PeerLifecycleEvent::Closing {
            generation: 6,
            reason: ant_quic::ConnectionCloseReason::TimedOut
        }
    );
    assert_eq!(
        events[6],
        PeerLifecycleEvent::Closed {
            generation: 6,
            reason: ant_quic::ConnectionCloseReason::TimedOut
        }
    );
    assert!(state.rows.windows(2).all(
        |rows| rows[0].sequence < rows[1].sequence && rows[0].elapsed_us <= rows[1].elapsed_us
    ));
}

#[tokio::test]
async fn lifecycle574_drop_cancels_unpolled_and_waiting_receivers() {
    for poll_first in [false, true] {
        let (tx, rx) = broadcast::channel(4);
        let mut trace = Trace::new();
        let journal = Arc::clone(&trace.journal);
        trace.attach(Side::Owner, Some(rx), PeerId([1; 32]));
        if poll_first {
            tokio::task::yield_now().await;
        }
        drop(trace);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while tx.receiver_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(journal.state.lock().unwrap().collectors_dropped[0]);
    }
}

#[tokio::test(start_paused = true)]
async fn lifecycle574_pending_snapshot_drops_without_advancing_deadline() {
    struct Pending(Arc<std::sync::atomic::AtomicBool>);
    impl Future for Pending {
        type Output = (bool, bool);
        fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let trace = Trace::new();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started = tokio::time::Instant::now();
    trace.snapshot(Side::Owner, Pending(Arc::clone(&dropped)));
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(started.elapsed(), std::time::Duration::ZERO);
    assert!(matches!(
        trace.journal.state.lock().unwrap().rows[0].observation,
        Observation::Snapshot(None)
    ));
    trace.finish().await;
}

#[tokio::test]
async fn lifecycle574_rows_are_bounded_and_overflow_is_explicit() {
    let mut trace = Trace::new();
    trace.attach(Side::Owner, None, PeerId([1; 32]));
    for _ in 0..ROW_LIMIT + 9 {
        trace.published(Side::Owner, Some(0));
    }
    trace.journal.update(|state| {
        assert_eq!(state.rows.len(), ROW_LIMIT);
        assert_eq!(state.total, (ROW_LIMIT + 10) as u64);
        assert_eq!(state.overflow, 10);
        assert!(matches!(
            state.rows[0].observation,
            Observation::StreamUnavailable
        ));
    });
    trace.finish().await;
}

#[tokio::test(start_paused = true)]
async fn lifecycle574_capture_deadline_and_event_limit_leave_explicit_gaps() {
    let peer = PeerId([1; 32]);
    let (tx, rx) = broadcast::channel(EVENT_LIMIT * 2);
    let trace = Trace::new();
    for generation in 0..=EVENT_LIMIT {
        tx.send((
            peer,
            PeerLifecycleEvent::Established {
                generation: generation as u64,
            },
        ))
        .unwrap();
    }
    Capture {
        receiver: rx,
        journal: Arc::clone(&trace.journal),
        side: Side::Owner,
        counterpart: peer,
    }
    .run()
    .await;
    trace.journal.update(|state| {
        assert_eq!(state.total, (EVENT_LIMIT + 1) as u64);
        assert_eq!(state.rows.len(), ROW_LIMIT);
        assert_eq!(state.pending_at_stop[0], 1);
        assert!(state.collectors_dropped[0]);
        assert!(!state.closed[0]);
    });
    trace.finish().await;

    let (_tx, rx) = broadcast::channel(4);
    let trace = Trace::new();
    let started = tokio::time::Instant::now();
    Capture {
        receiver: rx,
        journal: Arc::clone(&trace.journal),
        side: Side::Joiner,
        counterpart: peer,
    }
    .run()
    .await;
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(60));
    trace.journal.update(|state| {
        assert!(matches!(
            state.rows[0].observation,
            Observation::CaptureDeadline
        ));
        assert!(state.collectors_dropped[1]);
        assert!(!state.closed[1]);
    });
    trace.snapshot(Side::Owner, async { (true, false) });
    trace.journal.update(|state| {
        assert!(matches!(
            state.rows[1].observation,
            Observation::Snapshot(Some((true, false)))
        ))
    });
    trace.finish().await;
}
