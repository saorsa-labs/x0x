//! Wire protocol for Tier-1 remote exec frames.
//!
//! Frames are carried as normal x0x direct-message payloads, but every exec
//! payload starts with [`EXEC_DM_PREFIX`].  The DM inbox strips nothing; it
//! routes matching payloads away from generic `/direct/events` consumers, and
//! the exec service decodes the bincode frame after the prefix.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable payload prefix used to route exec frames before generic direct-message fan-out.
pub const EXEC_DM_PREFIX: &[u8] = b"x0x-exec-v1\0";

/// A client-allocated, 128-bit exec request/session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecRequestId(pub [u8; 16]);

impl ExecRequestId {
    /// Generate a new random request id.
    #[must_use]
    pub fn new_random() -> Self {
        let mut bytes = [0_u8; 16];
        use rand::RngCore as _;
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Parse a 32-character hex request id.
    pub fn from_hex(input: &str) -> Result<Self, ProtocolError> {
        let decoded =
            hex::decode(input).map_err(|e| ProtocolError::InvalidRequestId(e.to_string()))?;
        if decoded.len() != 16 {
            return Err(ProtocolError::InvalidRequestId(format!(
                "expected 16 bytes, got {}",
                decoded.len()
            )));
        }
        let mut out = [0_u8; 16];
        out.copy_from_slice(&decoded);
        Ok(Self(out))
    }

    /// Lowercase hex encoding.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for ExecRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Exec protocol frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecFrame {
    /// Client → server: request command execution.
    Request {
        request_id: ExecRequestId,
        argv: Vec<String>,
        stdin: Option<Vec<u8>>,
        timeout_ms: u32,
        /// Requester-controlled CWD is intentionally rejected in v1 unless a
        /// future ACL revision explicitly allows it.
        cwd: Option<String>,
    },
    /// Client → server: renew the request lease.  Missing renewals cancel the
    /// remote child within the configured lease window.
    LeaseRenew { request_id: ExecRequestId },
    /// Server → client: process spawned.
    Started { request_id: ExecRequestId, pid: u32 },
    /// Server → client: stdout chunk.
    Stdout {
        request_id: ExecRequestId,
        seq: u32,
        data: Vec<u8>,
    },
    /// Server → client: stderr chunk.
    Stderr {
        request_id: ExecRequestId,
        seq: u32,
        data: Vec<u8>,
    },
    /// Server → client: non-terminal warning.
    Warning {
        request_id: ExecRequestId,
        kind: WarningKind,
        message: String,
    },
    /// Server → client: terminal frame.
    Exit {
        request_id: ExecRequestId,
        code: Option<i32>,
        signal: Option<i32>,
        duration_ms: u64,
        stdout_bytes_total: u64,
        stderr_bytes_total: u64,
        truncated: bool,
        denial_reason: Option<DenialReason>,
    },
    /// Client → server: cancel an in-flight session.
    Cancel { request_id: ExecRequestId },
}

/// Output stream selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

/// Soft warning type sent to the requester and recorded in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WarningKind {
    StdoutCapHit,
    StderrCapHit,
    DurationApproachingCap,
    StdoutApproachingCap,
    StderrApproachingCap,
    LeaseExpired,
    PeerDisconnected,
    Cancelled,
}

impl WarningKind {
    /// Stable snake_case string for JSON diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StdoutCapHit => "stdout_cap_hit",
            Self::StderrCapHit => "stderr_cap_hit",
            Self::DurationApproachingCap => "duration_approaching_cap",
            Self::StdoutApproachingCap => "stdout_approaching_cap",
            Self::StderrApproachingCap => "stderr_approaching_cap",
            Self::LeaseExpired => "lease_expired",
            Self::PeerDisconnected => "peer_disconnected",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Denial reason returned in the terminal Exit frame and audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenialReason {
    ExecDisabled,
    UnverifiedSender,
    TrustRejected,
    AgentMachineNotInAcl,
    ArgvNotAllowed,
    StdinTooLarge,
    TimeoutTooLarge,
    CwdNotAllowed,
    ConcurrencyLimitReached,
    ShellMetacharInArgv,
    SpawnFailed,
    MalformedFrame,
}

impl DenialReason {
    /// Stable snake_case string for APIs/diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecDisabled => "exec_disabled",
            Self::UnverifiedSender => "unverified_sender",
            Self::TrustRejected => "trust_rejected",
            Self::AgentMachineNotInAcl => "agent_machine_not_in_acl",
            Self::ArgvNotAllowed => "argv_not_allowed",
            Self::StdinTooLarge => "stdin_too_large",
            Self::TimeoutTooLarge => "timeout_too_large",
            Self::CwdNotAllowed => "cwd_not_allowed",
            Self::ConcurrencyLimitReached => "concurrency_limit_reached",
            Self::ShellMetacharInArgv => "shell_metachar_in_argv",
            Self::SpawnFailed => "spawn_failed",
            Self::MalformedFrame => "malformed_frame",
        }
    }
}

/// Aggregated result returned by local API/CLI callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRunResult {
    pub request_id: ExecRequestId,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_bytes_total: u64,
    pub stderr_bytes_total: u64,
    pub truncated: bool,
    pub denial_reason: Option<DenialReason>,
    pub warnings: Vec<WarningKind>,
}

/// Protocol encode/decode failures.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("payload is not an x0x exec frame")]
    MissingPrefix,
    #[error("invalid exec frame: {0}")]
    Decode(String),
    #[error("invalid request id: {0}")]
    InvalidRequestId(String),
}

/// Encode a frame with the routing prefix.
pub fn encode_frame_payload(frame: &ExecFrame) -> Result<Vec<u8>, ProtocolError> {
    let encoded = bincode::serialize(frame).map_err(|e| ProtocolError::Decode(e.to_string()))?;
    let mut payload = Vec::with_capacity(EXEC_DM_PREFIX.len().saturating_add(encoded.len()));
    payload.extend_from_slice(EXEC_DM_PREFIX);
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

/// Decode an exec payload after verifying the routing prefix.
pub fn decode_frame_payload(payload: &[u8]) -> Result<ExecFrame, ProtocolError> {
    let Some(frame_bytes) = payload.strip_prefix(EXEC_DM_PREFIX) else {
        return Err(ProtocolError::MissingPrefix);
    };
    bincode::deserialize(frame_bytes).map_err(|e| ProtocolError::Decode(e.to_string()))
}
