//! Call lifecycle signalling (ADR-0073 slice 1, #892).
//!
//! Slice 1 ships the *lifecycle* only — invite, accept, reject, hangup,
//! the 30 s missed-call timeout, and the access-control gate that decides
//! whether an invite rings. There is no media path yet (the loopback
//! str0m gateway and `POST /calls/{id}/media` are later slices).
//!
//! # Wire format (ADR-0073 decision 2)
//!
//! Lifecycle frames are additive `x0x_call_*` extension frames on the
//! existing voice DM channel: the payload is
//! [`crate::history::classify::VOICE_SIGNALING_DM_PREFIX`]
//! (`x0x-voice-sig-v1\n`) followed by a JSON object whose `"type"` tag is
//! one of `x0x_call_invite`, `x0x_call_accept`, `x0x_call_reject`,
//! `x0x_call_hangup`. Every frame carries `call_id` and the media kinds.
//! The prefix keeps them Ephemeral under ADR-0023. Old peers ignore them:
//! a pre-extension `X0xSignaling` reader fails `SignalingMessage` decoding
//! on the unknown tag and drops the frame, and the ADR-0042 datagram
//! advert listener only matches its own `x0x_datagram_cap` tag.
//!
//! # Access control (ADR-0073 decision 4)
//!
//! An invite rings only if the caller passes the gates its media would
//! hit: the identity gate (`streams::stream_gate` — not revoked, not
//! expired, trust `Accept`) and, when the connect ACL is Enabled, the
//! `stream_acl_gate` pair check. Anything else is refused without
//! ringing, counted, and surfaced locally as `call.state{ended: refused}`.
//! [`crate::calls::CallRegistry::on_invite`] is the single enforcement point that turns
//! a gate verdict into "ring" or "refuse".

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::NetworkError;
use crate::identity::{AgentId, MachineId};

pub use crate::history::classify::VOICE_SIGNALING_DM_PREFIX as CALL_FRAME_PREFIX;

/// Unanswered invites end as `missed` after this long (ADR-0073 §3).
pub const INVITE_TIMEOUT_MS: u64 = 30_000;

/// Maximum concurrently live (not ended) calls. Bounds memory against an
/// invite flood from gate-passing peers; excess invites are dropped and
/// counted, excess outgoing calls are refused with [`CallError::TooManyCalls`].
pub const MAX_LIVE_CALLS: usize = 8;

/// Ended calls retained for `GET /calls` (oldest pruned first).
pub const MAX_ENDED_RETAINED: usize = 32;

/// Media kinds a call carries. Slice 1 always requests audio; `video` is
/// the caller's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaKinds {
    /// Audio requested.
    #[serde(default)]
    pub audio: bool,
    /// Video requested.
    #[serde(default)]
    pub video: bool,
}

/// One `x0x_call_*` lifecycle frame. Unknown fields are ignored so richer
/// future frames still decode (additive contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CallFrame {
    /// Caller → callee: ring.
    #[serde(rename = "x0x_call_invite")]
    Invite {
        /// Call identifier (32 lowercase hex chars).
        call_id: String,
        /// Requested media kinds.
        media: MediaKinds,
    },
    /// Callee → caller: answered.
    #[serde(rename = "x0x_call_accept")]
    Accept {
        /// Call identifier.
        call_id: String,
        /// Media kinds the callee accepts.
        media: MediaKinds,
    },
    /// Callee → caller: declined.
    #[serde(rename = "x0x_call_reject")]
    Reject {
        /// Call identifier.
        call_id: String,
        /// Media kinds of the declined call.
        media: MediaKinds,
    },
    /// Either side: end the call (also cancels a ringing invite).
    #[serde(rename = "x0x_call_hangup")]
    Hangup {
        /// Call identifier.
        call_id: String,
        /// Media kinds of the ended call.
        media: MediaKinds,
        /// Optional machine-readable reason (e.g. `missed`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl CallFrame {
    /// The frame's call identifier.
    #[must_use]
    pub fn call_id(&self) -> &str {
        match self {
            Self::Invite { call_id, .. }
            | Self::Accept { call_id, .. }
            | Self::Reject { call_id, .. }
            | Self::Hangup { call_id, .. } => call_id,
        }
    }

    /// Encode as a DM payload (`prefix || json`).
    ///
    /// # Errors
    /// Returns the serde error if encoding fails (it cannot for these types).
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        let body = serde_json::to_vec(self)?;
        let mut payload = Vec::with_capacity(CALL_FRAME_PREFIX.len() + body.len());
        payload.extend_from_slice(CALL_FRAME_PREFIX);
        payload.extend_from_slice(&body);
        Ok(payload)
    }

    /// Decode a DM payload. Returns `None` for anything that is not a
    /// well-formed `x0x_call_*` frame with a valid `call_id` — other voice
    /// signalling (upstream `SignalingMessage`s, the datagram advert,
    /// future extensions) is left to its own consumers.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let body = payload.strip_prefix(CALL_FRAME_PREFIX)?;
        let frame: Self = serde_json::from_slice(body).ok()?;
        is_valid_call_id(frame.call_id()).then_some(frame)
    }
}

/// A fresh random call identifier (128 bits, lowercase hex).
#[must_use]
pub fn new_call_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Whether `id` has the call-id shape (exactly 32 lowercase hex chars).
#[must_use]
pub fn is_valid_call_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Which side placed the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallDirection {
    /// This daemon placed the call.
    Outgoing,
    /// A peer called this daemon.
    Incoming,
}

/// Call lifecycle state (ADR-0073 §3 `call.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    /// Invite sent / received, not yet answered.
    Ringing,
    /// Answered; the media leg is being set up. Slice 1 has no media path,
    /// so an answered call stays here until hung up — `active` is reached
    /// only once the media gateway (a later slice) reports media flowing.
    Connecting,
    /// Media flowing (reserved for the media slice).
    Active,
    /// Ended; see [`EndReason`].
    Ended,
}

/// Why a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// This side hung up (or cancelled its ringing invite).
    Hangup,
    /// The peer hung up.
    RemoteHangup,
    /// This side declined the incoming invite.
    Rejected,
    /// The peer declined our invite.
    RemoteRejected,
    /// Nobody answered within [`INVITE_TIMEOUT_MS`].
    Missed,
    /// The caller failed the access-control gate; it never rang.
    Refused,
    /// A lifecycle frame could not be delivered to the peer.
    Failed,
}

/// Why an invite (or outgoing call) was refused at the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRefusal {
    /// Peer agent or machine is revoked.
    Revoked,
    /// No verified identity binding (unknown machine, expired cert, dead
    /// pairing, or unverified DM).
    NotVerified,
    /// Trust decision is not `Accept` (Unknown, Known, blocked, machine
    /// mismatch).
    Untrusted,
    /// Connect ACL is Enabled and the `(agent, machine)` pair is unlisted.
    NotInConnectAcl,
}

impl CallRefusal {
    /// Map a stream-gate error onto a refusal reason. Anything that is not
    /// an explicit revoke / trust / ACL denial fails closed as
    /// [`CallRefusal::NotVerified`].
    #[must_use]
    pub fn from_gate_error(err: &NetworkError) -> Self {
        match err {
            NetworkError::PeerRevoked { .. } => Self::Revoked,
            NetworkError::PeerTrustRejected { .. } => Self::Untrusted,
            NetworkError::PeerNotInConnectAcl { .. } => Self::NotInConnectAcl,
            _ => Self::NotVerified,
        }
    }
}

/// Serializable view of one call — the `call` object in REST responses
/// and the `data` of `call.incoming` / `call.state` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallSnapshot {
    /// Call identifier.
    pub call_id: String,
    /// The remote agent (64 lowercase hex chars).
    pub peer: String,
    /// Which side placed the call.
    pub direction: CallDirection,
    /// Requested media kinds.
    pub media: MediaKinds,
    /// Lifecycle state.
    pub state: CallState,
    /// Set iff `state == ended`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<EndReason>,
    /// Set on `refused` events: which gate refused the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<CallRefusal>,
    /// Unix ms when the call was created locally.
    pub created_at_ms: u64,
    /// Unix ms of the last state change.
    pub updated_at_ms: u64,
}

/// A local event for the `/events` SSE and `/ws` channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallEvent {
    /// `call.incoming` — an invite passed the gate and is ringing.
    Incoming(CallSnapshot),
    /// `call.state` — a lifecycle transition.
    State(CallSnapshot),
}

impl CallEvent {
    /// Event type name on the wire.
    #[must_use]
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Incoming(_) => "call.incoming",
            Self::State(_) => "call.state",
        }
    }

    /// The snapshot carried by the event.
    #[must_use]
    pub fn snapshot(&self) -> &CallSnapshot {
        match self {
            Self::Incoming(s) | Self::State(s) => s,
        }
    }
}

/// Errors from local lifecycle actions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// No call with that id.
    #[error("call not found")]
    NotFound,
    /// The action is not valid in the call's current state/direction.
    #[error("call is {0:?}; action not allowed")]
    InvalidState(CallState),
    /// [`MAX_LIVE_CALLS`] live calls already exist.
    #[error("too many live calls")]
    TooManyCalls,
}

/// Counters exposed on `GET /calls` (`stats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CallStats {
    /// Invites received (any outcome).
    pub invites_received: u64,
    /// Invites that passed the gate and rang.
    pub invites_rang: u64,
    /// Invites refused at the gate (sum of the `refused_*` counters).
    pub invites_refused: u64,
    /// Refusals: revoked caller.
    pub refused_revoked: u64,
    /// Refusals: unverified caller.
    pub refused_not_verified: u64,
    /// Refusals: untrusted caller (Unknown trust included).
    pub refused_untrusted: u64,
    /// Refusals: connect-ACL pair not listed.
    pub refused_not_in_connect_acl: u64,
    /// Invites dropped because [`MAX_LIVE_CALLS`] were live.
    pub invites_dropped_capacity: u64,
    /// Duplicate or colliding invites ignored.
    pub invites_ignored: u64,
    /// Calls that ended as missed.
    pub missed: u64,
}

#[derive(Debug, Clone)]
struct CallRecord {
    peer: AgentId,
    direction: CallDirection,
    media: MediaKinds,
    state: CallState,
    reason: Option<EndReason>,
    created_at_ms: u64,
    updated_at_ms: u64,
}

/// Outcome of a remote frame: local events plus an optional reply frame.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FrameOutcome {
    /// Events to broadcast locally.
    pub events: Vec<CallEvent>,
    /// Frame to send back to the peer, if any.
    pub reply: Option<CallFrame>,
}

/// Pure call-lifecycle state machine. Time is passed in (unix ms) so the
/// timeout path is unit-testable; the daemon owns I/O.
#[derive(Debug, Default)]
pub struct CallRegistry {
    calls: HashMap<String, CallRecord>,
    stats: CallStats,
}

impl CallRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Counters snapshot.
    #[must_use]
    pub fn stats(&self) -> CallStats {
        self.stats
    }

    /// Snapshot of one call.
    #[must_use]
    pub fn get(&self, call_id: &str) -> Option<CallSnapshot> {
        self.calls.get(call_id).map(|r| snapshot(call_id, r))
    }

    /// All retained calls, newest first.
    #[must_use]
    pub fn list(&self) -> Vec<CallSnapshot> {
        let mut out: Vec<CallSnapshot> = self.calls.iter().map(|(id, r)| snapshot(id, r)).collect();
        out.sort_by(|a, b| {
            b.created_at_ms
                .cmp(&a.created_at_ms)
                .then_with(|| a.call_id.cmp(&b.call_id))
        });
        out
    }

    fn live_count(&self) -> usize {
        self.calls
            .values()
            .filter(|r| r.state != CallState::Ended)
            .count()
    }

    /// Place an outgoing call. The caller has already cleared the
    /// outbound gate and sends the returned invite frame.
    ///
    /// # Errors
    /// [`CallError::TooManyCalls`] when [`MAX_LIVE_CALLS`] are live.
    pub fn start_outgoing(
        &mut self,
        peer: AgentId,
        media: MediaKinds,
        now_ms: u64,
    ) -> Result<(CallFrame, Vec<CallEvent>), CallError> {
        if self.live_count() >= MAX_LIVE_CALLS {
            return Err(CallError::TooManyCalls);
        }
        let call_id = new_call_id();
        self.calls.insert(
            call_id.clone(),
            CallRecord {
                peer,
                direction: CallDirection::Outgoing,
                media,
                state: CallState::Ringing,
                reason: None,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            },
        );
        self.prune_ended();
        let event = CallEvent::State(self.snapshot_of(&call_id)?);
        Ok((CallFrame::Invite { call_id, media }, vec![event]))
    }

    /// **The ring decision.** Handle an inbound invite from `caller` whose
    /// access-control verdict is `gate` (computed by the daemon from the
    /// real identity + connect-ACL gates). A refused caller never rings:
    /// no `call.incoming` is produced, the refusal is counted, and only a
    /// local `call.state{ended: refused}` event is returned. Nothing is
    /// sent back to a refused caller (no trust-state leak).
    pub fn on_invite(
        &mut self,
        caller: AgentId,
        gate: Result<(), CallRefusal>,
        call_id: &str,
        media: MediaKinds,
        now_ms: u64,
    ) -> Vec<CallEvent> {
        self.stats.invites_received = self.stats.invites_received.saturating_add(1);
        if let Err(refusal) = gate {
            self.count_refusal(refusal);
            return vec![CallEvent::State(CallSnapshot {
                call_id: call_id.to_owned(),
                peer: hex::encode(caller.0),
                direction: CallDirection::Incoming,
                media,
                state: CallState::Ended,
                reason: Some(EndReason::Refused),
                refusal: Some(refusal),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            })];
        }
        if !is_valid_call_id(call_id) || self.calls.contains_key(call_id) {
            // Duplicate (retransmit) or colliding id: never re-ring.
            self.stats.invites_ignored = self.stats.invites_ignored.saturating_add(1);
            return Vec::new();
        }
        if self.live_count() >= MAX_LIVE_CALLS {
            self.stats.invites_dropped_capacity =
                self.stats.invites_dropped_capacity.saturating_add(1);
            return Vec::new();
        }
        self.calls.insert(
            call_id.to_owned(),
            CallRecord {
                peer: caller,
                direction: CallDirection::Incoming,
                media,
                state: CallState::Ringing,
                reason: None,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            },
        );
        self.prune_ended();
        self.stats.invites_rang = self.stats.invites_rang.saturating_add(1);
        self.get(call_id)
            .map(CallEvent::Incoming)
            .into_iter()
            .collect()
    }

    fn count_refusal(&mut self, refusal: CallRefusal) {
        let s = &mut self.stats;
        s.invites_refused = s.invites_refused.saturating_add(1);
        let slot = match refusal {
            CallRefusal::Revoked => &mut s.refused_revoked,
            CallRefusal::NotVerified => &mut s.refused_not_verified,
            CallRefusal::Untrusted => &mut s.refused_untrusted,
            CallRefusal::NotInConnectAcl => &mut s.refused_not_in_connect_acl,
        };
        *slot = slot.saturating_add(1);
    }

    /// Answer a ringing incoming call. Returns the peer and the accept
    /// frame to send.
    ///
    /// # Errors
    /// [`CallError::NotFound`] / [`CallError::InvalidState`].
    pub fn accept(
        &mut self,
        call_id: &str,
        now_ms: u64,
    ) -> Result<(AgentId, CallFrame, Vec<CallEvent>), CallError> {
        let rec = self.calls.get_mut(call_id).ok_or(CallError::NotFound)?;
        if rec.direction != CallDirection::Incoming || rec.state != CallState::Ringing {
            return Err(CallError::InvalidState(rec.state));
        }
        rec.state = CallState::Connecting;
        rec.updated_at_ms = now_ms;
        let (peer, media) = (rec.peer, rec.media);
        let event = CallEvent::State(self.snapshot_of(call_id)?);
        Ok((
            peer,
            CallFrame::Accept {
                call_id: call_id.to_owned(),
                media,
            },
            vec![event],
        ))
    }

    /// Decline a ringing incoming call.
    ///
    /// # Errors
    /// [`CallError::NotFound`] / [`CallError::InvalidState`].
    pub fn reject(
        &mut self,
        call_id: &str,
        now_ms: u64,
    ) -> Result<(AgentId, CallFrame, Vec<CallEvent>), CallError> {
        let rec = self.calls.get(call_id).ok_or(CallError::NotFound)?;
        if rec.direction != CallDirection::Incoming || rec.state != CallState::Ringing {
            return Err(CallError::InvalidState(rec.state));
        }
        let (peer, media) = (rec.peer, rec.media);
        let event = self.end(call_id, EndReason::Rejected, now_ms)?;
        Ok((
            peer,
            CallFrame::Reject {
                call_id: call_id.to_owned(),
                media,
            },
            vec![event],
        ))
    }

    /// Hang up (or cancel) any live call.
    ///
    /// # Errors
    /// [`CallError::NotFound`] / [`CallError::InvalidState`] (already ended).
    pub fn hangup(
        &mut self,
        call_id: &str,
        now_ms: u64,
    ) -> Result<(AgentId, CallFrame, Vec<CallEvent>), CallError> {
        let rec = self.calls.get(call_id).ok_or(CallError::NotFound)?;
        if rec.state == CallState::Ended {
            return Err(CallError::InvalidState(rec.state));
        }
        let (peer, media) = (rec.peer, rec.media);
        let event = self.end(call_id, EndReason::Hangup, now_ms)?;
        Ok((
            peer,
            CallFrame::Hangup {
                call_id: call_id.to_owned(),
                media,
                reason: None,
            },
            vec![event],
        ))
    }

    /// Mark a live call ended because a lifecycle frame could not be
    /// delivered. No-op (no event) if the call is already ended.
    pub fn fail(&mut self, call_id: &str, now_ms: u64) -> Vec<CallEvent> {
        match self.calls.get(call_id) {
            Some(rec) if rec.state != CallState::Ended => self
                .end(call_id, EndReason::Failed, now_ms)
                .ok()
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Handle a non-invite frame from `from`. Invites go through
    /// [`Self::on_invite`]. A frame naming a call with a different peer is
    /// ignored — a third party cannot end or answer someone else's call.
    pub fn on_remote_frame(
        &mut self,
        from: AgentId,
        frame: &CallFrame,
        now_ms: u64,
    ) -> FrameOutcome {
        let call_id = frame.call_id();
        let Some(rec) = self.calls.get(call_id) else {
            // Late accept for a call we no longer know: tell the peer to
            // stop so it does not sit in `connecting` forever.
            return match frame {
                CallFrame::Accept { media, .. } => FrameOutcome {
                    events: Vec::new(),
                    reply: Some(CallFrame::Hangup {
                        call_id: call_id.to_owned(),
                        media: *media,
                        reason: Some("ended".to_owned()),
                    }),
                },
                _ => FrameOutcome::default(),
            };
        };
        if rec.peer != from {
            return FrameOutcome::default();
        }
        let (direction, state, media) = (rec.direction, rec.state, rec.media);
        match frame {
            CallFrame::Accept { .. } => {
                if direction == CallDirection::Outgoing && state == CallState::Ringing {
                    if let Some(rec) = self.calls.get_mut(call_id) {
                        rec.state = CallState::Connecting;
                        rec.updated_at_ms = now_ms;
                    }
                    return FrameOutcome {
                        events: self
                            .snapshot_of(call_id)
                            .map(CallEvent::State)
                            .into_iter()
                            .collect(),
                        reply: None,
                    };
                }
                if state == CallState::Ended {
                    // Accept raced our timeout/hangup: tell the callee.
                    return FrameOutcome {
                        events: Vec::new(),
                        reply: Some(CallFrame::Hangup {
                            call_id: call_id.to_owned(),
                            media,
                            reason: Some("ended".to_owned()),
                        }),
                    };
                }
                FrameOutcome::default()
            }
            CallFrame::Reject { .. } => {
                if direction == CallDirection::Outgoing && state == CallState::Ringing {
                    return FrameOutcome {
                        events: self
                            .end(call_id, EndReason::RemoteRejected, now_ms)
                            .into_iter()
                            .collect(),
                        reply: None,
                    };
                }
                FrameOutcome::default()
            }
            CallFrame::Hangup { .. } => {
                if state == CallState::Ended {
                    return FrameOutcome::default();
                }
                FrameOutcome {
                    events: self
                        .end(call_id, EndReason::RemoteHangup, now_ms)
                        .into_iter()
                        .collect(),
                    reply: None,
                }
            }
            CallFrame::Invite { .. } => FrameOutcome::default(),
        }
    }

    /// End every call that has been ringing for at least
    /// [`INVITE_TIMEOUT_MS`] as `missed`. Returns the events plus, for our
    /// own unanswered invites, the hangup frames that stop the callee's
    /// ring.
    pub fn expire(&mut self, now_ms: u64) -> (Vec<CallEvent>, Vec<(AgentId, CallFrame)>) {
        let expired: Vec<String> = self
            .calls
            .iter()
            .filter(|(_, r)| {
                r.state == CallState::Ringing
                    && now_ms.saturating_sub(r.created_at_ms) >= INVITE_TIMEOUT_MS
            })
            .map(|(id, _)| id.clone())
            .collect();
        let mut events = Vec::with_capacity(expired.len());
        let mut frames = Vec::new();
        for call_id in expired {
            let Some(rec) = self.calls.get(&call_id) else {
                continue;
            };
            if rec.direction == CallDirection::Outgoing {
                frames.push((
                    rec.peer,
                    CallFrame::Hangup {
                        call_id: call_id.clone(),
                        media: rec.media,
                        reason: Some("missed".to_owned()),
                    },
                ));
            }
            if let Ok(event) = self.end(&call_id, EndReason::Missed, now_ms) {
                self.stats.missed = self.stats.missed.saturating_add(1);
                events.push(event);
            }
        }
        (events, frames)
    }

    fn end(
        &mut self,
        call_id: &str,
        reason: EndReason,
        now_ms: u64,
    ) -> Result<CallEvent, CallError> {
        let rec = self.calls.get_mut(call_id).ok_or(CallError::NotFound)?;
        rec.state = CallState::Ended;
        rec.reason = Some(reason);
        rec.updated_at_ms = now_ms;
        let event = CallEvent::State(self.snapshot_of(call_id)?);
        self.prune_ended();
        Ok(event)
    }

    fn snapshot_of(&self, call_id: &str) -> Result<CallSnapshot, CallError> {
        self.get(call_id).ok_or(CallError::NotFound)
    }

    fn prune_ended(&mut self) {
        let mut ended: Vec<(u64, String)> = self
            .calls
            .iter()
            .filter(|(_, r)| r.state == CallState::Ended)
            .map(|(id, r)| (r.updated_at_ms, id.clone()))
            .collect();
        if ended.len() <= MAX_ENDED_RETAINED {
            return;
        }
        ended.sort();
        let excess = ended.len() - MAX_ENDED_RETAINED;
        for (_, id) in ended.into_iter().take(excess) {
            self.calls.remove(&id);
        }
    }
}

fn snapshot(call_id: &str, r: &CallRecord) -> CallSnapshot {
    CallSnapshot {
        call_id: call_id.to_owned(),
        peer: hex::encode(r.peer.0),
        direction: r.direction,
        media: r.media,
        state: r.state,
        reason: r.reason,
        refusal: None,
        created_at_ms: r.created_at_ms,
        updated_at_ms: r.updated_at_ms,
    }
}

impl crate::Agent {
    /// Inbound call gate (ADR-0073 decision 4): the verdict for an invite
    /// or accept from `caller` whose DM arrived from `machine`.
    ///
    /// Applies exactly the gates the call's media will hit on the inbound
    /// accept path — every agent on the machine must clear
    /// `streams::stream_gate` (revoked → expired → trust `Accept`) and,
    /// when the connect ACL is Enabled, `streams::stream_acl_gate` — plus
    /// the DM must be signature-verified and `caller` must be one of the
    /// machine's live agents.
    ///
    /// ADR-0070 / #924 × ADR-0073 (#980): a caller that fails ONLY on trust
    /// (never on revocation, expiry or the connect ACL) is admitted when it
    /// holds a live, unrevoked, unexpired `ShareGrant` carrying `Call` for
    /// this daemon's agent — the same `OwnerTrust::grant_access` lookup the
    /// Connect grant uses. Nothing else is bypassed: see
    /// `Agent::gate_peer_machine_inbound_with_call_grant`.
    pub(crate) async fn call_gate_inbound(
        &self,
        caller: &AgentId,
        machine: &MachineId,
        dm_verified: bool,
    ) -> Result<(), CallRefusal> {
        Self::call_gate_inbound_with(
            &self.identity_discovery_cache,
            &self.contact_store,
            &self.revocation_set,
            &self.move_state,
            &self.connect_policy,
            &self.owner_trust,
            caller,
            machine,
            dm_verified,
        )
        .await
    }

    /// [`Self::call_gate_inbound`] over explicit state, so the verdict is
    /// unit-testable without a network.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn call_gate_inbound_with(
        discovery_cache: &std::sync::Arc<
            tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>,
        >,
        contact_store: &std::sync::Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
        revocation_set: &std::sync::Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
        move_state: &std::sync::Arc<tokio::sync::RwLock<crate::key_move::MoveState>>,
        connect_policy: &std::sync::Arc<
            std::sync::RwLock<std::sync::Arc<crate::connect::ConnectPolicy>>,
        >,
        owner_trust: &crate::owner_trust::OwnerTrust,
        caller: &AgentId,
        machine: &MachineId,
        dm_verified: bool,
    ) -> Result<(), CallRefusal> {
        if !dm_verified {
            return Err(CallRefusal::NotVerified);
        }
        let agents = Self::gate_peer_machine_inbound_with_call_grant(
            discovery_cache,
            contact_store,
            revocation_set,
            move_state,
            connect_policy,
            owner_trust,
            machine,
            None, // RED(#980): gate change reverted on ci-mirror only
        )
        .await
        .map_err(|e| CallRefusal::from_gate_error(&e))?;
        if !agents.contains(caller) {
            return Err(CallRefusal::NotVerified);
        }
        Ok(())
    }

    /// Outbound call gate: the callee must pass the same identity gate
    /// (`gate_peer_outbound`) and, when the connect ACL is Enabled, be
    /// pair-listed — otherwise its media could never reach us.
    pub(crate) async fn call_gate_outbound(&self, callee: &AgentId) -> Result<(), CallRefusal> {
        let machine = self
            .gate_peer_outbound(callee)
            .await
            .map_err(|e| CallRefusal::from_gate_error(&e))?;
        let policy = {
            let guard = self
                .connect_policy
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::sync::Arc::clone(&guard)
        };
        // ADR-0070 §1: an owner-trusted callee is listed by a
        // `principal = "owner"` ACL entry, exactly as on the inbound path.
        let owner_trusted = self
            .owner_trust
            .evaluate_pair(
                &self.contact_store,
                &self.identity_discovery_cache,
                &self.revocation_set,
                callee,
                &machine,
            )
            .await
            .owner_trusted;
        let owner_trusted: &[AgentId] = if owner_trusted { &[*callee] } else { &[] };
        crate::streams::stream_acl_gate(&policy, &[*callee], owner_trusted, &machine)
            .map_err(|e| CallRefusal::from_gate_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::{Contact, ContactStore, IdentityType, TrustLevel};
    use crate::trust::{TrustContext, TrustEvaluator};

    const T0: u64 = 1_000_000;
    const AV: MediaKinds = MediaKinds {
        audio: true,
        video: true,
    };

    fn agent(b: u8) -> AgentId {
        AgentId([b; 32])
    }

    fn id(b: u8) -> String {
        hex::encode([b; 16])
    }

    /// The verdict the daemon computes for `caller`, built from the REAL
    /// trust evaluator and the REAL identity gate (`streams::stream_gate`)
    /// — not a hand-written `Err`. Caller is clean (not revoked, not
    /// expired); only the contact store's trust level varies.
    fn real_gate_verdict(store: &ContactStore, caller: &AgentId) -> Result<(), CallRefusal> {
        let machine = MachineId([7u8; 32]);
        let decision = TrustEvaluator::new(store).evaluate(&TrustContext {
            agent_id: caller,
            machine_id: &machine,
        });
        crate::streams::stream_gate(caller, Some(decision), false, false, false)
            .map_err(|e| CallRefusal::from_gate_error(&e))
    }

    fn store_with(caller: AgentId, trust: Option<TrustLevel>) -> (tempfile::TempDir, ContactStore) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        if let Some(trust_level) = trust {
            store.add(Contact {
                agent_id: caller,
                trust_level,
                label: None,
                added_at: 0,
                last_seen: None,
                identity_type: IdentityType::Anonymous,
                machines: Vec::new(),
                dm_capabilities: None,
            });
        }
        (dir, store)
    }

    fn has_incoming(events: &[CallEvent]) -> bool {
        events.iter().any(|e| matches!(e, CallEvent::Incoming(_)))
    }

    // WHY: ADR-0073 decision 4 / acceptance (e) — an Unknown-trust caller
    // must NEVER ring, and the refusal must be counted. This drives the
    // ring decision (`on_invite`) with the verdict the real trust
    // evaluator + stream gate produce for a caller absent from contacts.
    // If `on_invite` ignored the gate verdict, the `!has_incoming`
    // assertion fails (an Incoming event would be produced) and so do the
    // counter assertions (`invites_refused` would stay 0, `invites_rang`
    // would be 1).
    #[test]
    fn unknown_trust_caller_never_rings_and_is_counted() {
        let caller = agent(0xAA);
        let (_dir, store) = store_with(caller, None);
        let verdict = real_gate_verdict(&store, &caller);
        assert_eq!(
            verdict,
            Err(CallRefusal::Untrusted),
            "Unknown trust must fail the gate"
        );

        let mut reg = CallRegistry::new();
        let events = reg.on_invite(caller, verdict, &id(1), AV, T0);

        assert!(
            !has_incoming(&events),
            "an Unknown-trust caller rang: {events:?}"
        );
        let stats = reg.stats();
        assert_eq!(stats.invites_refused, 1, "refusal not counted");
        assert_eq!(
            stats.refused_untrusted, 1,
            "refusal not attributed to trust"
        );
        assert_eq!(stats.invites_rang, 0);
        // Only the local refused event, and no call record retained.
        assert_eq!(events.len(), 1);
        let snap = events[0].snapshot();
        assert_eq!(events[0].event_type(), "call.state");
        assert_eq!(snap.state, CallState::Ended);
        assert_eq!(snap.reason, Some(EndReason::Refused));
        assert_eq!(snap.refusal, Some(CallRefusal::Untrusted));
        assert!(reg.get(&id(1)).is_none());
        assert!(reg.list().is_empty());
    }

    // WHY: Known is not Trusted — AcceptWithFlag must not ring either
    // (mirrors stream_gate: only plain Accept passes).
    #[test]
    fn known_but_not_trusted_caller_never_rings() {
        let caller = agent(0xAB);
        let (_dir, store) = store_with(caller, Some(TrustLevel::Known));
        let mut reg = CallRegistry::new();
        let events = reg.on_invite(caller, real_gate_verdict(&store, &caller), &id(2), AV, T0);
        assert!(!has_incoming(&events));
        assert_eq!(reg.stats().refused_untrusted, 1);
    }

    // Control for the two tests above: the same path with a Trusted
    // contact DOES ring. Without this, a registry that never rings would
    // pass the refusal tests.
    #[test]
    fn trusted_caller_rings() {
        let caller = agent(0xAC);
        let (_dir, store) = store_with(caller, Some(TrustLevel::Trusted));
        let verdict = real_gate_verdict(&store, &caller);
        assert_eq!(verdict, Ok(()));
        let mut reg = CallRegistry::new();
        let events = reg.on_invite(caller, verdict, &id(3), AV, T0);
        assert!(has_incoming(&events), "a Trusted caller must ring");
        assert_eq!(events[0].event_type(), "call.incoming");
        assert_eq!(events[0].snapshot().state, CallState::Ringing);
        let stats = reg.stats();
        assert_eq!((stats.invites_rang, stats.invites_refused), (1, 0));
    }

    #[test]
    fn every_refusal_reason_is_counted_separately() {
        let mut reg = CallRegistry::new();
        for (i, r) in [
            CallRefusal::Revoked,
            CallRefusal::NotVerified,
            CallRefusal::Untrusted,
            CallRefusal::NotInConnectAcl,
        ]
        .into_iter()
        .enumerate()
        {
            let events = reg.on_invite(agent(1), Err(r), &id(10 + i as u8), AV, T0);
            assert!(!has_incoming(&events));
        }
        let s = reg.stats();
        assert_eq!(s.invites_refused, 4);
        assert_eq!(
            (
                s.refused_revoked,
                s.refused_not_verified,
                s.refused_untrusted,
                s.refused_not_in_connect_acl
            ),
            (1, 1, 1, 1)
        );
    }

    // WHY: the full happy path on BOTH ends must reach ended within one
    // frame each way (acceptance (f)). Drives two registries through the
    // wire frames they hand each other.
    #[test]
    fn offer_accept_hangup_lifecycle() {
        let (alice, bob) = (agent(1), agent(2));
        let mut a = CallRegistry::new();
        let mut b = CallRegistry::new();

        let (invite, ev) = a.start_outgoing(bob, AV, T0).expect("start");
        assert_eq!(ev[0].snapshot().state, CallState::Ringing);
        assert_eq!(ev[0].snapshot().direction, CallDirection::Outgoing);
        let wire = CallFrame::decode(&invite.encode().expect("encode")).expect("decode");
        let CallFrame::Invite { call_id, media } = wire else {
            panic!("expected invite, got {wire:?}");
        };

        let ev = b.on_invite(alice, Ok(()), &call_id, media, T0 + 10);
        assert!(has_incoming(&ev));

        let (to, accept, ev) = b.accept(&call_id, T0 + 20).expect("accept");
        assert_eq!(to, alice);
        assert_eq!(ev[0].snapshot().state, CallState::Connecting);
        let out = a.on_remote_frame(bob, &accept, T0 + 30);
        assert_eq!(out.reply, None);
        assert_eq!(out.events[0].snapshot().state, CallState::Connecting);

        let (to, hangup, ev) = a.hangup(&call_id, T0 + 40).expect("hangup");
        assert_eq!(to, bob);
        assert_eq!(ev[0].snapshot().reason, Some(EndReason::Hangup));
        let out = b.on_remote_frame(alice, &hangup, T0 + 50);
        assert_eq!(out.events[0].snapshot().state, CallState::Ended);
        assert_eq!(
            out.events[0].snapshot().reason,
            Some(EndReason::RemoteHangup)
        );

        // Ended is terminal.
        assert_eq!(
            a.hangup(&call_id, T0 + 60).map(|_| ()),
            Err(CallError::InvalidState(CallState::Ended))
        );
        assert_eq!(
            b.accept(&call_id, T0 + 60).map(|_| ()),
            Err(CallError::InvalidState(CallState::Ended))
        );
    }

    #[test]
    fn reject_ends_both_sides() {
        let (alice, bob) = (agent(1), agent(2));
        let mut a = CallRegistry::new();
        let mut b = CallRegistry::new();
        let (invite, _) = a.start_outgoing(bob, AV, T0).expect("start");
        let call_id = invite.call_id().to_owned();
        b.on_invite(alice, Ok(()), &call_id, AV, T0);
        let (_, reject, ev) = b.reject(&call_id, T0 + 5).expect("reject");
        assert_eq!(ev[0].snapshot().reason, Some(EndReason::Rejected));
        let out = a.on_remote_frame(bob, &reject, T0 + 6);
        assert_eq!(
            out.events[0].snapshot().reason,
            Some(EndReason::RemoteRejected)
        );
        // The caller cannot "accept" its own outgoing call.
        let (invite2, _) = a.start_outgoing(bob, AV, T0).expect("start");
        assert!(matches!(
            a.accept(invite2.call_id(), T0),
            Err(CallError::InvalidState(_))
        ));
    }

    // WHY: ADR-0073 §3 — unanswered invites end as `missed` after 30 s on
    // both sides, and the caller tells the callee so its ring stops.
    #[test]
    fn unanswered_invite_times_out_as_missed() {
        let (alice, bob) = (agent(1), agent(2));
        let mut a = CallRegistry::new();
        let mut b = CallRegistry::new();
        let (invite, _) = a.start_outgoing(bob, AV, T0).expect("start");
        let call_id = invite.call_id().to_owned();
        b.on_invite(alice, Ok(()), &call_id, AV, T0);

        // One ms before the deadline nothing expires.
        let (ev, frames) = a.expire(T0 + INVITE_TIMEOUT_MS - 1);
        assert!(ev.is_empty() && frames.is_empty());

        let (ev, frames) = a.expire(T0 + INVITE_TIMEOUT_MS);
        assert_eq!(ev[0].snapshot().reason, Some(EndReason::Missed));
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, bob);
        assert!(matches!(&frames[0].1, CallFrame::Hangup { reason: Some(r), .. } if r == "missed"));
        assert_eq!(a.stats().missed, 1);

        // Callee expires independently (its own clock) and sends nothing.
        let (ev, frames) = b.expire(T0 + INVITE_TIMEOUT_MS);
        assert_eq!(ev[0].snapshot().reason, Some(EndReason::Missed));
        assert!(frames.is_empty());

        // A late accept after the caller's timeout gets a hangup back.
        let late = CallFrame::Accept { call_id, media: AV };
        let out = a.on_remote_frame(bob, &late, T0 + INVITE_TIMEOUT_MS + 1);
        assert!(matches!(out.reply, Some(CallFrame::Hangup { .. })));
        assert!(out.events.is_empty());
    }

    #[test]
    fn third_party_frames_and_duplicate_invites_are_ignored() {
        let (alice, mallory) = (agent(1), agent(3));
        let mut b = CallRegistry::new();
        let call_id = id(9);
        assert!(has_incoming(&b.on_invite(alice, Ok(()), &call_id, AV, T0)));
        // Retransmitted invite never re-rings.
        assert!(b.on_invite(alice, Ok(()), &call_id, AV, T0).is_empty());
        assert_eq!(b.stats().invites_ignored, 1);
        // Mallory cannot hang up Alice's call.
        let hangup = CallFrame::Hangup {
            call_id: call_id.clone(),
            media: AV,
            reason: None,
        };
        assert_eq!(
            b.on_remote_frame(mallory, &hangup, T0),
            FrameOutcome::default()
        );
        assert_eq!(b.get(&call_id).map(|s| s.state), Some(CallState::Ringing));
    }

    #[test]
    fn live_calls_are_bounded() {
        let mut reg = CallRegistry::new();
        for i in 0..MAX_LIVE_CALLS {
            reg.on_invite(agent(1), Ok(()), &id(i as u8), AV, T0);
        }
        assert_eq!(
            reg.start_outgoing(agent(2), AV, T0).map(|_| ()),
            Err(CallError::TooManyCalls)
        );
        assert!(reg.on_invite(agent(1), Ok(()), &id(200), AV, T0).is_empty());
        assert_eq!(reg.stats().invites_dropped_capacity, 1);
    }

    // WHY: REST/event JSON shapes are protocol surface for the GUI and
    // agents (ADR-0073 §3). Pin them.
    #[test]
    fn snapshot_and_event_json_shapes_are_pinned() {
        let mut reg = CallRegistry::new();
        let ev = reg.on_invite(agent(0x01), Ok(()), &id(0x0c), AV, 42);
        let json = serde_json::to_value(ev[0].snapshot()).expect("json");
        assert_eq!(
            json,
            serde_json::json!({
                "call_id": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                "peer": "01".repeat(32),
                "direction": "incoming",
                "media": {"audio": true, "video": true},
                "state": "ringing",
                "created_at_ms": 42,
                "updated_at_ms": 42,
            })
        );
        let (_, _, ev) = reg.reject(&id(0x0c), 43).expect("reject");
        let json = serde_json::to_value(ev[0].snapshot()).expect("json");
        assert_eq!(json["state"], "ended");
        assert_eq!(json["reason"], "rejected");

        let refused = reg.on_invite(agent(2), Err(CallRefusal::Untrusted), &id(0x0d), AV, 44);
        let json = serde_json::to_value(refused[0].snapshot()).expect("json");
        assert_eq!(json["reason"], "refused");
        assert_eq!(json["refusal"], "untrusted");

        let stats = serde_json::to_value(reg.stats()).expect("json");
        for key in [
            "invites_received",
            "invites_rang",
            "invites_refused",
            "refused_revoked",
            "refused_not_verified",
            "refused_untrusted",
            "refused_not_in_connect_acl",
            "invites_dropped_capacity",
            "invites_ignored",
            "missed",
        ] {
            assert!(stats.get(key).is_some(), "stats missing {key}");
        }
    }

    // WHY: the frame names and field set are the ADR-0073 wire contract;
    // renaming them silently breaks calls between versions.
    #[test]
    fn frame_wire_shape_is_pinned() {
        let frame = CallFrame::Invite {
            call_id: id(0xab),
            media: MediaKinds {
                audio: true,
                video: false,
            },
        };
        let payload = frame.encode().expect("encode");
        assert!(payload.starts_with(b"x0x-voice-sig-v1\n"));
        let body: serde_json::Value =
            serde_json::from_slice(&payload[CALL_FRAME_PREFIX.len()..]).expect("json");
        assert_eq!(
            body,
            serde_json::json!({
                "type": "x0x_call_invite",
                "call_id": id(0xab),
                "media": {"audio": true, "video": false},
            })
        );
        for (tag, f) in [
            (
                "x0x_call_accept",
                CallFrame::Accept {
                    call_id: id(1),
                    media: AV,
                },
            ),
            (
                "x0x_call_reject",
                CallFrame::Reject {
                    call_id: id(1),
                    media: AV,
                },
            ),
            (
                "x0x_call_hangup",
                CallFrame::Hangup {
                    call_id: id(1),
                    media: AV,
                    reason: None,
                },
            ),
        ] {
            let v = serde_json::to_value(&f).expect("json");
            assert_eq!(v["type"], tag);
            assert_eq!(CallFrame::decode(&f.encode().expect("encode")), Some(f));
        }
        // A malformed call_id (34 chars) is rejected by the shape check.
        let mut newer = CALL_FRAME_PREFIX.to_vec();
        newer.extend_from_slice(
            br#"{"type":"x0x_call_hangup","call_id":"0101010101010101010101010101010101","media":{"audio":true},"future":1}"#,
        );
        assert_eq!(CallFrame::decode(&newer), None);
        // Additive: unknown fields from a newer peer still decode.
        let mut newer_ok = CALL_FRAME_PREFIX.to_vec();
        newer_ok.extend_from_slice(
            format!(r#"{{"type":"x0x_call_hangup","call_id":"{}","media":{{"audio":true}},"future":1}}"#, id(1)).as_bytes(),
        );
        assert!(matches!(
            CallFrame::decode(&newer_ok),
            Some(CallFrame::Hangup { .. })
        ));
        // Not ours: upstream signalling, the datagram advert, no prefix.
        let mut upstream = CALL_FRAME_PREFIX.to_vec();
        upstream.extend_from_slice(br#"{"type":"connection_ready","session_id":"s"}"#);
        assert_eq!(CallFrame::decode(&upstream), None);
        let mut advert = CALL_FRAME_PREFIX.to_vec();
        advert.extend_from_slice(br#"{"type":"x0x_datagram_cap","datagram":true}"#);
        assert_eq!(CallFrame::decode(&advert), None);
        assert_eq!(CallFrame::decode(br#"{"type":"x0x_call_invite"}"#), None);
    }

    /// #980 (ADR-0073 × ADR-0070): the inbound call gate admits a caller
    /// that fails ONLY on trust when it holds a live `Call` ShareGrant for
    /// this daemon's agent — and nothing else. Every test drives the real
    /// gate (`Agent::call_gate_inbound_with`, the body of
    /// `call_gate_inbound`) over the real grant store, authenticated
    /// bindings, revocation set and connect ACL; no network.
    mod call_grant {
        use super::*;
        use crate::connect::{ConnectAcl, ConnectAllowEntry, ConnectPolicy};
        use crate::identity::{AgentCertificate, AgentKeypair, UserKeypair};
        use crate::owner_trust::OwnerTrust;
        use crate::revocation::RevocationSet;
        use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        fn real_now() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }

        /// Owner A's daemon hosting callee agent A1. User B's agent B1 on
        /// machine MB is a stranger (no contact entry) with an authenticated
        /// binding and an owner-B certificate in the discovery cache.
        struct World {
            dir: tempfile::TempDir,
            owner_a: UserKeypair,
            a1: AgentId,
            user_b: UserKeypair,
            b1: AgentId,
            mb: MachineId,
            contacts: Arc<RwLock<ContactStore>>,
            cache: Arc<RwLock<HashMap<AgentId, crate::DiscoveredAgent>>>,
            revocations: Arc<RwLock<RevocationSet>>,
            bindings: crate::dm_inbox::AuthenticatedMachineBindings,
            move_state: Arc<RwLock<crate::key_move::MoveState>>,
        }

        impl World {
            async fn new() -> Self {
                let dir = tempfile::tempdir().expect("tmpdir");
                let owner_a = UserKeypair::generate().expect("owner a");
                let user_b = UserKeypair::generate().expect("user b");
                let a1 = AgentKeypair::generate().expect("a1").agent_id();
                let b1_kp = AgentKeypair::generate().expect("b1");
                let b1 = b1_kp.agent_id();
                let mb = MachineId([0xB0; 32]);
                let bindings = crate::dm_inbox::AuthenticatedMachineBindings::default();
                crate::dm_inbox::record_authenticated_machine_binding(
                    &bindings,
                    b1,
                    mb,
                    real_now(),
                )
                .await;
                let cert = AgentCertificate::issue(&user_b, &b1_kp).expect("cert");
                let entry = crate::DiscoveredAgent {
                    self_name: None,
                    agent_id: b1,
                    machine_id: mb,
                    user_id: cert.user_id().ok(),
                    addresses: Vec::new(),
                    announced_at: 0,
                    last_seen: 0,
                    machine_public_key: Vec::new(),
                    nat_type: None,
                    can_receive_direct: None,
                    is_relay: None,
                    is_coordinator: None,
                    reachable_via: Vec::new(),
                    relay_candidates: Vec::new(),
                    cert_not_after: cert.not_after(),
                    agent_certificate: Some(cert),
                    agent_public_key: b1_kp.public_key().as_bytes().to_vec(),
                    cert_digest: None,
                };
                let mut cache = HashMap::new();
                cache.insert(b1, entry);
                let contacts = ContactStore::new(dir.path().join("contacts.json"));
                Self {
                    dir,
                    owner_a,
                    a1,
                    user_b,
                    b1,
                    mb,
                    contacts: Arc::new(RwLock::new(contacts)),
                    cache: Arc::new(RwLock::new(cache)),
                    revocations: Arc::new(RwLock::new(RevocationSet::new())),
                    bindings,
                    move_state: Arc::new(RwLock::new(crate::key_move::MoveState::default())),
                }
            }

            /// A grant from owner A to user B over A1.
            fn grant(&self, caps: Vec<ShareCap>, not_before: u64, expiry: u64) -> ShareGrant {
                ShareGrant::sign(
                    &self.owner_a,
                    [0x44; 32],
                    Grantee::User(self.user_b.user_id()),
                    vec![self.a1],
                    caps,
                    not_before,
                    expiry,
                )
                .expect("sign grant")
            }

            /// Owner-trust source of A1's daemon holding `grants` (each
            /// accepted inside its own window).
            async fn daemon(&self, grants: &[ShareGrant]) -> OwnerTrust {
                let store = ShareGrantStore::in_memory(self.a1, Some(self.owner_a.user_id()));
                for grant in grants {
                    store
                        .accept(grant.clone(), grant.not_before)
                        .await
                        .expect("accept grant");
                }
                let trust =
                    OwnerTrust::new(Some(self.owner_a.user_id()), Arc::clone(&self.bindings));
                trust.install_share_grant_store(Arc::new(store));
                trust
            }

            /// The inbound call verdict for B1 ringing A1 from MB.
            async fn ring(
                &self,
                trust: &OwnerTrust,
                policy: ConnectPolicy,
            ) -> Result<(), CallRefusal> {
                let policy = Arc::new(std::sync::RwLock::new(Arc::new(policy)));
                crate::Agent::call_gate_inbound_with(
                    &self.cache,
                    &self.contacts,
                    &self.revocations,
                    &self.move_state,
                    &policy,
                    trust,
                    &self.b1,
                    &self.mb,
                    true,
                )
                .await
            }

            /// Owner A revokes `grant` over the real `x0x.revocation.v3`
            /// ingest path.
            async fn revoke(&self, grant: &ShareGrant) {
                let record = crate::revocation::RevocationRecord::sign(
                    crate::revocation::RevokedSubject::ShareGrant(
                        crate::revocation::ShareGrantRevocation {
                            grant_id: grant.grant_id,
                            owner: grant.owner,
                            grant_expiry: grant.expiry,
                        },
                    ),
                    self.owner_a.public_key(),
                    self.owner_a.secret_key(),
                    real_now(),
                    None,
                )
                .expect("sign revocation");
                let payload = bincode::serialize(&vec![record]).expect("encode");
                assert!(
                    crate::ingest_share_grant_revocations(
                        &self.revocations,
                        Some(self.dir.path().to_path_buf()),
                        &payload,
                    )
                    .await,
                    "the owner's v3 revocation must be accepted"
                );
            }
        }

        fn acl(entries: Vec<ConnectAllowEntry>) -> ConnectPolicy {
            ConnectPolicy::Enabled(ConnectAcl {
                loaded_from: std::path::PathBuf::from("/test/connect-acl.toml"),
                loaded_at_unix_ms: 0,
                allow: entries,
                owner_allow: Vec::new(),
                grant_allow: Vec::new(),
            })
        }

        fn listed(agent: AgentId, machine: MachineId) -> ConnectAllowEntry {
            ConnectAllowEntry {
                description: None,
                agent_id: agent,
                machine_id: machine,
                targets: vec!["127.0.0.1:22".parse().expect("addr")],
            }
        }

        // WHY (a): a stranger holding a live Call grant for the callee rings
        // without a contact entry. The control shows the same caller with
        // no grant is refused on trust, so the admit comes from the grant.
        // Fails if `call_gate_inbound` stops passing the caller to the
        // Call-grant promotion (it would be refused `Untrusted`).
        #[tokio::test]
        async fn call_grantee_is_admitted() {
            let w = World::new().await;
            let now = real_now();
            let none = w.daemon(&[]).await;
            assert_eq!(
                w.ring(&none, ConnectPolicy::default()).await,
                Err(CallRefusal::Untrusted),
                "control: an ungranted stranger fails on trust"
            );
            let trust = w
                .daemon(&[w.grant(vec![ShareCap::Call], now - 60, now + 3_600)])
                .await;
            assert_eq!(w.ring(&trust, ConnectPolicy::default()).await, Ok(()));
        }

        // WHY (b): the same grantee is refused once owner A revokes the grant
        // on x0x.revocation.v3, at the next evaluation and without restart.
        #[tokio::test]
        async fn call_grantee_is_refused_after_revocation() {
            let w = World::new().await;
            let now = real_now();
            let grant = w.grant(vec![ShareCap::Call], now - 60, now + 3_600);
            let trust = w.daemon(std::slice::from_ref(&grant)).await;
            assert_eq!(
                w.ring(&trust, ConnectPolicy::default()).await,
                Ok(()),
                "control: live grant admits"
            );
            w.revoke(&grant).await;
            assert_eq!(
                w.ring(&trust, ConnectPolicy::default()).await,
                Err(CallRefusal::Untrusted)
            );
        }

        // WHY (c): a Call grant that was live when accepted but whose expiry
        // has passed confers nothing — the grantee is refused on trust.
        #[tokio::test]
        async fn call_grantee_is_refused_after_expiry() {
            let w = World::new().await;
            let now = real_now();
            let live = w
                .daemon(&[w.grant(vec![ShareCap::Call], now - 60, now + 3_600)])
                .await;
            assert_eq!(
                w.ring(&live, ConnectPolicy::default()).await,
                Ok(()),
                "control: the same grantee with a live grant is admitted"
            );
            let expired = w
                .daemon(&[w.grant(vec![ShareCap::Call], now - 7_200, now - 60)])
                .await;
            assert_eq!(
                w.ring(&expired, ConnectPolicy::default()).await,
                Err(CallRefusal::Untrusted)
            );
        }

        // WHY (d): only the Call cap rings. A live Dm-only grant (proved
        // live by its `dm` access) is refused, so the promotion is keyed on
        // `Call`, not on "holds any grant".
        #[tokio::test]
        async fn dm_only_grant_is_refused() {
            let w = World::new().await;
            let now = real_now();
            let trust = w
                .daemon(&[w.grant(vec![ShareCap::Dm], now - 60, now + 3_600)])
                .await;
            let access = trust
                .grant_access(&w.contacts, &w.cache, &w.revocations, &w.b1, &w.mb)
                .await;
            assert!(access.dm && !access.call, "control: the Dm grant is live");
            assert_eq!(
                w.ring(&trust, ConnectPolicy::default()).await,
                Err(CallRefusal::Untrusted)
            );
        }

        // WHY (e): a Call grant is not an ACL bypass. With the connect ACL
        // Enabled and B1 unlisted, the grantee is refused `NotInConnectAcl`;
        // pair-listing B1 (control) admits it, and the listing alone without
        // the grant still fails on trust.
        #[tokio::test]
        async fn call_grant_does_not_override_acl_denial() {
            let w = World::new().await;
            let now = real_now();
            let trust = w
                .daemon(&[w.grant(vec![ShareCap::Call], now - 60, now + 3_600)])
                .await;
            let other = AgentKeypair::generate().expect("other").agent_id();
            assert_eq!(
                w.ring(&trust, acl(vec![listed(other, w.mb)])).await,
                Err(CallRefusal::NotInConnectAcl)
            );
            assert_eq!(
                w.ring(&trust, acl(vec![listed(w.b1, w.mb)])).await,
                Ok(()),
                "control: a listed grantee is admitted"
            );
            let none = w.daemon(&[]).await;
            assert_eq!(
                w.ring(&none, acl(vec![listed(w.b1, w.mb)])).await,
                Err(CallRefusal::Untrusted),
                "control: listing alone does not replace trust or the grant"
            );
        }
    }
}
