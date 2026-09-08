//! Optional, bounded diagnostics for the ignored voice churn fixture.
//!
//! No media or error strings are retained. A completed write is not an ACK.
//! Stream IDs can repeat across connections; generation hints are temporal
//! observations only. The recorder never queries or repairs a connection.
//! Pinned ant-quic 0.27.50 drops unfinished send streams with reset code
//! 0xA17C0244 unless connection error/invalid 0-RTT applies. This recorder
//! observes local destruction; it does not finish streams or prove reset delivery.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ant_quic::high_level::{ReadError, ReadExactError, WriteError};
use serde::Serialize;

const STREAM_CAP: usize = 64;
const EVENT_CAP: usize = 128;
const PHASE_CAP: usize = 16;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Stage {
    Opening,
    TypePrefix,
    FrameLength,
    FramePayload,
    Forwarding,
    Idle,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Cause {
    BoundaryEof,
    Truncated { filled: usize },
    Reset { code: u64 },
    Stopped { code: u64 },
    LocallyClosed,
    ConnectionLost,
    ClosedStream,
    ZeroRttRejected,
    IllegalOrderedRead,
    InvalidType,
    InvalidLength,
    ConsumerClosed,
    OpenError,
    Timeout,
    CancelledOrDropped,
    EvictedWriteError,
    EvictedTimeout,
    PrefixDiscard,
    Stop,
    DroppedUnknownOwner,
}

fn read_cause(stage: Stage, error: &ReadExactError) -> Cause {
    match error {
        ReadExactError::FinishedEarly(0) if stage == Stage::FrameLength => Cause::BoundaryEof,
        ReadExactError::FinishedEarly(filled) => Cause::Truncated { filled: *filled },
        ReadExactError::ReadError(error) => match error {
            ReadError::Reset(code) => Cause::Reset {
                code: code.into_inner(),
            },
            ReadError::ConnectionLost(ant_quic::ConnectionError::LocallyClosed) => {
                Cause::LocallyClosed
            }
            ReadError::ConnectionLost(_) => Cause::ConnectionLost,
            ReadError::ClosedStream => Cause::ClosedStream,
            ReadError::ZeroRttRejected => Cause::ZeroRttRejected,
            ReadError::IllegalOrderedRead => Cause::IllegalOrderedRead,
        },
    }
}

fn write_cause(error: &WriteError) -> Cause {
    match error {
        WriteError::Stopped(code) => Cause::Stopped {
            code: code.into_inner(),
        },
        WriteError::ConnectionLost(ant_quic::ConnectionError::LocallyClosed) => {
            Cause::LocallyClosed
        }
        WriteError::ConnectionLost(_) => Cause::ConnectionLost,
        WriteError::ClosedStream => Cause::ClosedStream,
        WriteError::ZeroRttRejected => Cause::ZeroRttRejected,
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Stamp {
    sequence: u64,
    micros: u128,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Totals {
    logical_sends: u64,
    physical_attempts: u64,
    completed_writes: u64,
    written_payload_bytes: u64,
    valid_lengths: u64,
    fully_read: u64,
    forwarded: u64,
    consumed_audio: u64,
    consumed_data: u64,
    consumed_other: u64,
    write_errors: u64,
    write_timeouts: u64,
    cancelled_operations: u64,
    inbound_terminals: u64,
    outbound_destructions: u64,
}

#[derive(Clone, Debug, Serialize)]
struct Row {
    instance: u64,
    inbound: bool,
    peer_machine: Option<[u8; 32]>,
    quic_stream: Option<u64>,
    stream_type: Option<u8>,
    direction: &'static str,
    generation_association: &'static str,
    generation_before_open: Option<u64>,
    generation_after_open: Option<u64>,
    opened: Stamp,
    updated: Stamp,
    stage: Stage,
    prefix_complete: bool,
    physical_attempts: u64,
    completed_writes: u64,
    written_payload_bytes: u64,
    valid_lengths: u64,
    fully_read: u64,
    forwarded: u64,
    write_errors: u64,
    write_timeouts: u64,
    cancelled_operations: u64,
    last_failure: Option<(Stage, Cause)>,
    terminal: Option<(Stage, Cause)>,
    write_operation_active: bool,
}

#[derive(Clone, Debug, Serialize)]
struct Lifecycle {
    at: Stamp,
    kind: &'static str,
    generation: u64,
    old_generation: Option<u64>,
    reason: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct SideState {
    side: &'static str,
    expected_peer: [u8; 32],
    sequence: u64,
    generation_hint: Option<u64>,
    totals: Totals,
    rows: Vec<Row>,
    next_instance: u64,
    inbound_rows: usize,
    outbound_rows: usize,
    omitted_streams: u64,
    lifecycle: Vec<Lifecycle>,
    omitted_events: u64,
    foreign_events: u64,
    lag_batches: u64,
    lag_events: u64,
    subscription: &'static str,
}

impl SideState {
    fn new(side: &'static str, expected_peer: [u8; 32]) -> Self {
        Self {
            side,
            expected_peer,
            sequence: 0,
            generation_hint: None,
            totals: Totals::default(),
            rows: Vec::new(),
            next_instance: 0,
            inbound_rows: 0,
            outbound_rows: 0,
            omitted_streams: 0,
            lifecycle: Vec::new(),
            omitted_events: 0,
            foreign_events: 0,
            lag_batches: 0,
            lag_events: 0,
            subscription: "not_attached",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum Phase {
    PreChurn,
    Disconnect,
    Reconnected,
    PostSendStart,
    PostSendEnd,
    ReceiveStart,
    ReceiveEnd,
}

#[derive(Clone, Debug, Serialize)]
struct PhaseRecord {
    phase: Phase,
    micros: u128,
    totals: [Totals; 2],
}

#[derive(Serialize)]
struct Capture {
    #[serde(skip)]
    epoch: Instant,
    schema: &'static str,
    limitations: &'static str,
    closed_micros: Option<u128>,
    after_cut_updates: u64,
    sides: [SideState; 2],
    phases: Vec<PhaseRecord>,
    omitted_phases: u64,
}

/// An optional observation handle, scoped to one side of this test process.
#[derive(Clone)]
pub struct Observation {
    shared: Arc<Mutex<Capture>>,
    side: usize,
}

impl Observation {
    fn update(&self, f: impl FnOnce(&mut SideState, Stamp)) {
        let mut capture = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if capture.closed_micros.is_some() {
            capture.after_cut_updates = capture.after_cut_updates.saturating_add(1);
            return;
        }
        let micros = capture.epoch.elapsed().as_micros();
        let side = &mut capture.sides[self.side];
        side.sequence = side.sequence.saturating_add(1);
        let stamp = Stamp {
            sequence: side.sequence,
            micros,
        };
        f(side, stamp);
    }

    pub(crate) fn logical_send(&self) {
        self.update(|s, _| s.totals.logical_sends = s.totals.logical_sends.saturating_add(1));
    }

    /// Count only a frame already returned by the unchanged receive call.
    pub fn consumed(&self, stream_type: u8) {
        self.update(|s, _| {
            use saorsa_webrtc_core::link_transport::StreamType;
            let counter = if stream_type == StreamType::Audio.as_u8() {
                &mut s.totals.consumed_audio
            } else if stream_type == StreamType::Data.as_u8() {
                &mut s.totals.consumed_data
            } else {
                &mut s.totals.consumed_other
            };
            *counter = counter.saturating_add(1);
        });
    }

    fn lifecycle(&self, peer: ant_quic::PeerId, event: ant_quic::PeerLifecycleEvent) {
        self.update(|s, at| {
            if peer.0 != s.expected_peer {
                s.foreign_events = s.foreign_events.saturating_add(1);
                return;
            }
            use ant_quic::PeerLifecycleEvent::*;
            let (kind, generation, old_generation, reason) = match event {
                Established { generation } => {
                    s.generation_hint = Some(generation);
                    ("established", generation, None, None)
                }
                Replaced {
                    old_generation,
                    new_generation,
                } => {
                    s.generation_hint = Some(new_generation);
                    ("replaced", new_generation, Some(old_generation), None)
                }
                Closing { generation, reason } => {
                    ("closing", generation, None, Some(reason.as_str()))
                }
                Closed { generation, reason } => {
                    ("closed", generation, None, Some(reason.as_str()))
                }
                ReaderExited { generation } => ("reader_exited", generation, None, None),
            };
            // A terminal event is retained for its own generation only; it
            // never closes a voice row or identifies that row's connection.
            if s.lifecycle.len() < EVENT_CAP {
                s.lifecycle.push(Lifecycle {
                    at,
                    kind,
                    generation,
                    old_generation,
                    reason,
                });
            } else {
                s.omitted_events = s.omitted_events.saturating_add(1);
            }
        });
    }
}

/// Freezes both sides under one recorder mutex; owns only diagnostic tasks.
/// Drop prints on early return/unwind. Successful completion is quiet.
pub struct FailureCapture {
    shared: Arc<Mutex<Capture>>,
    observers: Vec<tokio::task::JoinHandle<()>>,
    passed: bool,
}

impl FailureCapture {
    /// Create before starting the observed voice transports.
    pub fn new(alice_remote: [u8; 32], bob_remote: [u8; 32]) -> Self {
        Self { shared: Arc::new(Mutex::new(Capture {
            epoch: Instant::now(), schema: "x0x.voice-churn-observation/1",
            limitations: "direction unknown; generation association temporal only; write completion is not delivery; failed write/read progress unknown except FinishedEarly; active rows are incomplete; post-cut updates excluded",
            closed_micros: None, after_cut_updates: 0,
            sides: [SideState::new("alice", alice_remote), SideState::new("bob", bob_remote)], phases: Vec::new(), omitted_phases: 0,
        })), observers: Vec::new(), passed: false }
    }

    pub fn alice(&self) -> Observation {
        Observation {
            shared: Arc::clone(&self.shared),
            side: 0,
        }
    }
    pub fn bob(&self) -> Observation {
        Observation {
            shared: Arc::clone(&self.shared),
            side: 1,
        }
    }

    /// Attach an already-created passive receiver, never a health query.
    pub fn subscribe(
        &mut self,
        observation: Observation,
        receiver: Option<
            tokio::sync::broadcast::Receiver<(ant_quic::PeerId, ant_quic::PeerLifecycleEvent)>,
        >,
    ) {
        if self.observers.len() == 2 {
            observation.update(|s, _| s.subscription = "observer_cap");
            return;
        }
        let Some(mut receiver) = receiver else {
            observation.update(|s, _| s.subscription = "unavailable");
            return;
        };
        observation.update(|s, _| s.subscription = "listening");
        self.observers.push(tokio::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok((peer, event)) => observation.lifecycle(peer, event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        observation.update(|s, _| {
                            s.lag_batches = s.lag_batches.saturating_add(1);
                            s.lag_events = s.lag_events.saturating_add(n);
                        })
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        observation.update(|s, _| s.subscription = "closed");
                        break;
                    }
                }
            }
        }));
    }

    pub fn phase(&self, phase: Phase) {
        let mut capture = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if capture.closed_micros.is_some() {
            capture.after_cut_updates = capture.after_cut_updates.saturating_add(1);
            return;
        }
        if capture.phases.len() == PHASE_CAP {
            capture.omitted_phases = capture.omitted_phases.saturating_add(1);
            return;
        }
        let record = PhaseRecord {
            phase,
            micros: capture.epoch.elapsed().as_micros(),
            totals: [
                capture.sides[0].totals.clone(),
                capture.sides[1].totals.clone(),
            ],
        };
        capture.phases.push(record);
    }

    /// Call only after the original assertions, before transport shutdown.
    pub fn passed(&mut self) {
        self.passed = true;
        self.close();
    }

    fn close(&mut self) {
        let mut capture = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if capture.closed_micros.is_none() {
            capture.closed_micros = Some(capture.epoch.elapsed().as_micros());
        }
        drop(capture);
        for observer in self.observers.drain(..) {
            observer.abort();
        }
    }
}

impl Drop for FailureCapture {
    fn drop(&mut self) {
        self.close();
        if !self.passed {
            let capture = self.shared.lock().unwrap_or_else(|p| p.into_inner());
            if let Ok(json) = serde_json::to_string(&*capture) {
                // Printing failures must not mask the original test panic.
                let _ = writeln!(std::io::stderr().lock(), "VOICE_CHURN_OBSERVATION {json}");
            }
        }
    }
}

/// Owns one local stream instance. Dropping an unfinished reader records
/// cancellation, including a spawned future that was never polled.
pub(crate) struct Token {
    observation: Option<Observation>,
    row: Option<usize>,
    inbound: bool,
    ended: bool,
}

impl Token {
    pub(crate) fn new(
        observation: Option<Observation>,
        inbound: bool,
        stream_type: Option<u8>,
    ) -> Self {
        let mut row = None;
        if let Some(obs) = &observation {
            obs.update(|s, at| {
                let instance = s.next_instance;
                s.next_instance = s.next_instance.saturating_add(1);
                let count = if inbound {
                    &mut s.inbound_rows
                } else {
                    &mut s.outbound_rows
                };
                if *count == STREAM_CAP {
                    s.omitted_streams = s.omitted_streams.saturating_add(1);
                    return;
                }
                *count += 1;
                row = Some(s.rows.len());
                s.rows.push(Row {
                    instance,
                    inbound,
                    peer_machine: None,
                    quic_stream: None,
                    stream_type,
                    direction: "unknown",
                    generation_association: if s.generation_hint.is_some() {
                        "temporal_only"
                    } else {
                        "unknown"
                    },
                    generation_before_open: s.generation_hint,
                    generation_after_open: None,
                    opened: at,
                    updated: at,
                    stage: if inbound {
                        Stage::TypePrefix
                    } else {
                        Stage::Opening
                    },
                    prefix_complete: false,
                    physical_attempts: 0,
                    completed_writes: 0,
                    written_payload_bytes: 0,
                    valid_lengths: 0,
                    fully_read: 0,
                    forwarded: 0,
                    write_errors: 0,
                    write_timeouts: 0,
                    cancelled_operations: 0,
                    last_failure: None,
                    terminal: None,
                    write_operation_active: false,
                });
            });
        }
        Self {
            observation,
            row,
            inbound,
            ended: false,
        }
    }

    fn update(&self, f: impl FnOnce(Option<&mut Row>, &mut Totals)) {
        if let Some(obs) = &self.observation {
            obs.update(|s, at| {
                let mut row = self.row.and_then(|i| s.rows.get_mut(i));
                if let Some(row) = &row {
                    if row.terminal.is_some() {
                        return;
                    }
                }
                if let Some(row) = row.as_mut() {
                    row.updated = at;
                }
                f(row, &mut s.totals);
            });
        }
    }

    pub(crate) fn identity(&self, peer: [u8; 32], stream: u64) {
        if let Some(obs) = &self.observation {
            obs.update(|s, at| {
                if let Some(row) = self.row.and_then(|i| s.rows.get_mut(i)) {
                    row.peer_machine = Some(peer);
                    row.quic_stream = Some(stream);
                    row.generation_after_open = s.generation_hint;
                    if row.generation_before_open.is_some() || row.generation_after_open.is_some() {
                        row.generation_association = "temporal_only";
                    }
                    row.updated = at;
                }
            });
        }
    }

    pub(crate) fn stage(&self, stage: Stage) {
        self.update(|row, _| {
            if let Some(row) = row {
                row.stage = stage;
            }
        });
    }
    pub(crate) fn prefix_complete(&self, stream_type: u8) {
        self.update(|row, _| {
            if let Some(row) = row {
                row.prefix_complete = true;
                row.stream_type = Some(stream_type);
                row.stage = Stage::Idle;
            }
        });
    }
    pub(crate) fn valid_length(&self) {
        self.update(|row, t| {
            t.valid_lengths = t.valid_lengths.saturating_add(1);
            if let Some(row) = row {
                row.valid_lengths = row.valid_lengths.saturating_add(1);
            }
        });
    }
    pub(crate) fn fully_read(&self) {
        self.update(|row, t| {
            t.fully_read = t.fully_read.saturating_add(1);
            if let Some(row) = row {
                row.fully_read = row.fully_read.saturating_add(1);
            }
        });
    }
    pub(crate) fn forwarded(&self) {
        self.update(|row, t| {
            t.forwarded = t.forwarded.saturating_add(1);
            if let Some(row) = row {
                row.forwarded = row.forwarded.saturating_add(1);
            }
        });
    }

    pub(crate) fn end(&mut self, cause: Cause) {
        if self.ended {
            return;
        }
        self.update(|row, t| {
            let counter = if self.inbound {
                &mut t.inbound_terminals
            } else {
                &mut t.outbound_destructions
            };
            *counter = counter.saturating_add(1);
            if let Some(row) = row {
                row.terminal = Some((row.stage, cause));
                row.write_operation_active = false;
            }
        });
        self.ended = true;
    }

    pub(crate) fn read_error(&mut self, stage: Stage, error: &ReadExactError) {
        self.end(read_cause(stage, error));
    }

    pub(crate) fn attempt(&self) -> Attempt {
        self.update(|row, t| {
            t.physical_attempts = t.physical_attempts.saturating_add(1);
            if let Some(row) = row {
                row.physical_attempts = row.physical_attempts.saturating_add(1);
                row.write_operation_active = true;
            }
        });
        Attempt {
            observation: self.observation.clone(),
            row: self.row,
            done: false,
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.end(if self.inbound {
            Cause::CancelledOrDropped
        } else {
            Cause::DroppedUnknownOwner
        });
    }
}

pub(crate) struct Attempt {
    observation: Option<Observation>,
    row: Option<usize>,
    done: bool,
}

impl Attempt {
    fn update(&self, f: impl FnOnce(Option<&mut Row>, &mut Totals)) {
        if let Some(obs) = &self.observation {
            obs.update(|s, at| {
                let mut row = self.row.and_then(|i| s.rows.get_mut(i));
                if let Some(row) = row.as_mut() {
                    row.updated = at;
                }
                f(row, &mut s.totals);
            });
        }
    }
    pub(crate) fn stage(&self, stage: Stage) {
        self.update(|row, _| {
            if let Some(row) = row {
                row.stage = stage;
            }
        });
    }
    pub(crate) fn complete(&mut self, bytes: usize) {
        self.update(|row, t| {
            t.completed_writes = t.completed_writes.saturating_add(1);
            t.written_payload_bytes = t.written_payload_bytes.saturating_add(bytes as u64);
            if let Some(row) = row {
                row.completed_writes = row.completed_writes.saturating_add(1);
                row.written_payload_bytes = row.written_payload_bytes.saturating_add(bytes as u64);
                row.stage = Stage::Idle;
                row.write_operation_active = false;
            }
        });
        self.done = true;
    }
    pub(crate) fn fail(&mut self, cause: Cause) {
        self.update(|row, t| {
            if cause == Cause::Timeout {
                t.write_timeouts = t.write_timeouts.saturating_add(1);
            } else {
                t.write_errors = t.write_errors.saturating_add(1);
            }
            if let Some(row) = row {
                if cause == Cause::Timeout {
                    row.write_timeouts = row.write_timeouts.saturating_add(1);
                } else {
                    row.write_errors = row.write_errors.saturating_add(1);
                }
                row.last_failure = Some((row.stage, cause));
                row.write_operation_active = false;
            }
        });
        self.done = true;
    }
    pub(crate) fn write_error(&mut self, error: &WriteError) {
        self.fail(write_cause(error));
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.done {
            self.update(|row, t| {
                t.cancelled_operations = t.cancelled_operations.saturating_add(1);
                if let Some(row) = row {
                    row.cancelled_operations = row.cancelled_operations.saturating_add(1);
                    row.write_operation_active = false;
                    row.last_failure = Some((row.stage, Cause::CancelledOrDropped));
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No Agent, NetworkNode, endpoint, stream, or socket construction.
    fn capture() -> FailureCapture {
        let mut capture = FailureCapture::new([1; 32], [2; 32]);
        capture.passed = true; // Keep pure controls quiet without freezing.
        capture
    }

    #[test]
    fn voice_observation_retry_counts_one_logical_send_two_attempts() {
        let capture = capture();
        let obs = capture.alice();
        obs.logical_send();
        let mut first = Token::new(Some(obs.clone()), false, Some(0x20));
        first.identity([1; 32], 4);
        let mut attempt = first.attempt();
        attempt.stage(Stage::FramePayload);
        attempt.fail(Cause::Timeout);
        first.end(Cause::EvictedTimeout);
        let second = Token::new(Some(obs), false, Some(0x20));
        second.identity([1; 32], 4); // Same QUIC ID, distinct local instance.
        let mut attempt = second.attempt();
        second.prefix_complete(0x20);
        attempt.complete(200);
        let state = capture.shared.lock().unwrap();
        let side = &state.sides[0];
        assert_eq!(side.totals.logical_sends, 1);
        assert_eq!(side.totals.physical_attempts, 2);
        assert_eq!(side.totals.completed_writes, 1);
        assert_eq!(side.totals.written_payload_bytes, 200);
        assert_ne!(side.rows[0].instance, side.rows[1].instance);
        assert_eq!(
            side.rows[0].last_failure,
            Some((Stage::FramePayload, Cause::Timeout))
        );
        assert!(side.rows[1].terminal.is_none());
    }

    #[test]
    fn voice_observation_prefix_and_second_error_are_retained() {
        let capture = capture();
        let obs = capture.alice();
        obs.logical_send();
        let mut first = Token::new(Some(obs.clone()), false, Some(0x20));
        let mut a = first.attempt();
        a.stage(Stage::TypePrefix);
        a.write_error(&WriteError::Stopped(ant_quic::VarInt::from_u32(17)));
        first.end(Cause::PrefixDiscard);
        let second = Token::new(Some(obs), false, Some(0x20));
        let mut b = second.attempt();
        b.stage(Stage::FrameLength);
        b.write_error(&WriteError::ConnectionLost(
            ant_quic::ConnectionError::LocallyClosed,
        ));
        let state = capture.shared.lock().unwrap();
        let side = &state.sides[0];
        assert_eq!(side.totals.write_errors, 2);
        assert_eq!(side.totals.completed_writes, 0);
        assert_eq!(
            side.rows[0].last_failure,
            Some((Stage::TypePrefix, Cause::Stopped { code: 17 }))
        );
        assert_eq!(
            side.rows[0].terminal,
            Some((Stage::TypePrefix, Cause::PrefixDiscard))
        );
        assert_eq!(
            side.rows[1].last_failure,
            Some((Stage::FrameLength, Cause::LocallyClosed))
        );
        // The production second-error branch retains its cached lane.
        assert!(side.rows[1].terminal.is_none());
    }

    #[test]
    fn voice_observation_typed_eof_reset_and_local_close() {
        assert_eq!(
            read_cause(Stage::FrameLength, &ReadExactError::FinishedEarly(0)),
            Cause::BoundaryEof
        );
        for stage in [Stage::TypePrefix, Stage::FramePayload] {
            assert_eq!(
                read_cause(stage, &ReadExactError::FinishedEarly(0)),
                Cause::Truncated { filled: 0 }
            );
        }
        assert_eq!(
            read_cause(Stage::FrameLength, &ReadExactError::FinishedEarly(2)),
            Cause::Truncated { filled: 2 }
        );
        let capture = capture();
        for stage in [Stage::FrameLength, Stage::FramePayload] {
            let mut token = Token::new(Some(capture.bob()), true, Some(0x20));
            token.stage(stage);
            token.read_error(
                stage,
                &ReadExactError::ReadError(ReadError::Reset(ant_quic::VarInt::from_u32(
                    0xA17C0244,
                ))),
            );
        }
        let state = capture.shared.lock().unwrap();
        assert_eq!(
            state.sides[1].rows[0].terminal,
            Some((Stage::FrameLength, Cause::Reset { code: 0xA17C0244 }))
        );
        assert_eq!(
            state.sides[1].rows[1].terminal,
            Some((Stage::FramePayload, Cause::Reset { code: 0xA17C0244 }))
        );
        drop(state);
        assert_eq!(
            read_cause(
                Stage::FrameLength,
                &ReadExactError::ReadError(ReadError::ConnectionLost(
                    ant_quic::ConnectionError::LocallyClosed
                ))
            ),
            Cause::LocallyClosed
        );
        assert_eq!(
            read_cause(
                Stage::FrameLength,
                &ReadExactError::ReadError(ReadError::ClosedStream)
            ),
            Cause::ClosedStream
        );
    }

    #[test]
    fn voice_observation_read_forward_consume_and_terminal_are_distinct() {
        let capture = capture();
        let mut reader = Token::new(Some(capture.bob()), true, None);
        reader.prefix_complete(0x20);
        reader.valid_length();
        reader.fully_read();
        reader.stage(Stage::Forwarding);
        reader.end(Cause::ConsumerClosed);
        reader.end(Cause::CancelledOrDropped);
        drop(reader);
        let reader = Token::new(Some(capture.bob()), true, None);
        reader.valid_length();
        reader.fully_read();
        reader.forwarded();
        reader.stage(Stage::FrameLength);
        drop(reader);
        let state = capture.shared.lock().unwrap();
        let side = &state.sides[1];
        assert_eq!(side.totals.fully_read, 2);
        assert_eq!(side.totals.forwarded, 1);
        assert_eq!(side.totals.consumed_audio, 0);
        assert_eq!(side.totals.inbound_terminals, 2);
        assert_eq!(
            side.rows[0].terminal,
            Some((Stage::Forwarding, Cause::ConsumerClosed))
        );
        assert_eq!(
            side.rows[1].terminal,
            Some((Stage::FrameLength, Cause::CancelledOrDropped))
        );
    }

    #[test]
    fn voice_observation_parser_rejections_retain_stage_and_no_forward() {
        let capture = capture();
        let mut reader = Token::new(Some(capture.bob()), true, None);
        reader.end(Cause::InvalidType);
        let mut reader = Token::new(Some(capture.bob()), true, Some(0x20));
        reader.stage(Stage::FrameLength);
        reader.end(Cause::InvalidLength);
        let state = capture.shared.lock().unwrap();
        let side = &state.sides[1];
        assert_eq!(
            side.rows[0].terminal,
            Some((Stage::TypePrefix, Cause::InvalidType))
        );
        assert_eq!(
            side.rows[1].terminal,
            Some((Stage::FrameLength, Cause::InvalidLength))
        );
        assert_eq!(side.totals.valid_lengths, 0);
        assert_eq!(side.totals.fully_read, 0);
        assert_eq!(side.totals.forwarded, 0);
    }

    #[test]
    fn voice_observation_generation_events_do_not_bind_or_close_streams() {
        let capture = capture();
        let obs = capture.alice();
        obs.lifecycle(
            ant_quic::PeerId([1; 32]),
            ant_quic::PeerLifecycleEvent::Established { generation: 7 },
        );
        let token = Token::new(Some(obs.clone()), false, Some(0x20));
        obs.lifecycle(
            ant_quic::PeerId([1; 32]),
            ant_quic::PeerLifecycleEvent::Replaced {
                old_generation: 7,
                new_generation: 8,
            },
        );
        token.identity([1; 32], 4);
        for event in [
            ant_quic::PeerLifecycleEvent::Closing {
                generation: 7,
                reason: ant_quic::ConnectionCloseReason::Superseded,
            },
            ant_quic::PeerLifecycleEvent::Closed {
                generation: 7,
                reason: ant_quic::ConnectionCloseReason::Superseded,
            },
        ] {
            obs.lifecycle(ant_quic::PeerId([1; 32]), event);
        }
        let state = capture.shared.lock().unwrap();
        let side = &state.sides[0];
        assert_eq!(side.generation_hint, Some(8));
        assert_eq!(side.rows[0].generation_before_open, Some(7));
        assert_eq!(side.rows[0].generation_after_open, Some(8));
        assert!(side.rows[0].terminal.is_none());
        assert_eq!(side.lifecycle.len(), 4);
        assert_eq!(side.lifecycle[2].kind, "closing");
        assert_eq!(side.lifecycle[3].kind, "closed");
        assert!(state.sides[1].lifecycle.is_empty());
    }

    #[test]
    fn voice_observation_caps_lag_unavailable_and_atomic_cut() {
        let mut capture = capture();
        let obs = capture.alice();
        capture.subscribe(obs.clone(), None);
        obs.update(|s, _| {
            s.lag_batches = 1;
            s.lag_events = 9;
        });
        for _ in 0..STREAM_CAP + 1 {
            let token = Token::new(Some(obs.clone()), true, None);
            token.fully_read();
        }
        for _ in 0..EVENT_CAP + 1 {
            obs.lifecycle(
                ant_quic::PeerId([1; 32]),
                ant_quic::PeerLifecycleEvent::ReaderExited { generation: 1 },
            );
        }
        obs.lifecycle(
            ant_quic::PeerId([3; 32]),
            ant_quic::PeerLifecycleEvent::ReaderExited { generation: 1 },
        );
        capture.phase(Phase::PostSendStart);
        let active = Token::new(Some(capture.bob()), true, None);
        capture.close();
        let before = {
            let state = capture.shared.lock().unwrap();
            let side = &state.sides[0];
            assert_eq!(side.rows.len(), STREAM_CAP);
            assert_eq!(side.omitted_streams, 1);
            assert_eq!(side.totals.fully_read, (STREAM_CAP + 1) as u64);
            assert_eq!(side.totals.inbound_terminals, (STREAM_CAP + 1) as u64);
            assert_eq!(side.lifecycle.len(), EVENT_CAP);
            assert_eq!(side.omitted_events, 1);
            assert_eq!(side.foreign_events, 1);
            assert_eq!(side.lag_events, 9);
            assert_eq!(side.subscription, "unavailable");
            assert!(state.sides[1].rows[0].terminal.is_none());
            serde_json::to_value(&state.sides).unwrap()
        };
        drop(active);
        obs.logical_send();
        let state = capture.shared.lock().unwrap();
        assert_eq!(serde_json::to_value(&state.sides).unwrap(), before);
        assert_eq!(state.after_cut_updates, 2);
    }

    #[test]
    fn voice_observation_cancelled_attempt_is_not_completed_or_terminal() {
        let capture = capture();
        let token = Token::new(Some(capture.alice()), false, Some(0x20));
        let attempt = token.attempt();
        attempt.stage(Stage::FramePayload);
        drop(attempt);
        let state = capture.shared.lock().unwrap();
        let side = &state.sides[0];
        assert_eq!(side.totals.cancelled_operations, 1);
        assert_eq!(side.totals.completed_writes, 0);
        assert!(side.rows[0].terminal.is_none());
        assert!(!side.rows[0].write_operation_active);
        assert_eq!(
            side.rows[0].last_failure,
            Some((Stage::FramePayload, Cause::CancelledOrDropped))
        );
        drop(state);
        drop(token);
        let state = capture.shared.lock().unwrap();
        assert_eq!(
            state.sides[0].rows[0].terminal,
            Some((Stage::FramePayload, Cause::DroppedUnknownOwner))
        );
    }
}
