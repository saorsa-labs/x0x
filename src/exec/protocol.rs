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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request_id() -> ExecRequestId {
        ExecRequestId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    }

    // ── ExecRequestId hex round-trip ──────────────────────────────────

    #[test]
    fn request_id_hex_roundtrip() {
        let id = test_request_id();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        let parsed = ExecRequestId::from_hex(&hex).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn request_id_display_matches_hex() {
        let id = test_request_id();
        assert_eq!(format!("{id}"), id.to_hex());
    }

    #[test]
    fn request_id_from_hex_rejects_odd_length() {
        assert!(ExecRequestId::from_hex("0123456789abcdef").is_err()); // 16 hex chars = 8 bytes
    }

    #[test]
    fn request_id_from_hex_rejects_too_short() {
        assert!(ExecRequestId::from_hex("0123456789abcdef0123456789abcde").is_err()); // 31 chars
    }

    #[test]
    fn request_id_from_hex_rejects_too_long() {
        assert!(ExecRequestId::from_hex("0123456789abcdef0123456789abcdef00").is_err()); // 34 chars = 17 bytes
    }

    #[test]
    fn request_id_from_hex_rejects_invalid_chars() {
        assert!(ExecRequestId::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn request_id_from_hex_empty_string() {
        assert!(ExecRequestId::from_hex("").is_err());
    }

    #[test]
    fn request_id_new_random_produces_unique_ids() {
        let a = ExecRequestId::new_random();
        let b = ExecRequestId::new_random();
        // Probability of collision is negligible
        assert_ne!(a, b);
    }

    // ── Frame encode/decode round-trip ────────────────────────────────

    #[test]
    fn encode_decode_request_frame() {
        let frame = ExecFrame::Request {
            request_id: test_request_id(),
            argv: vec!["echo".to_string(), "hello".to_string()],
            stdin: Some(b"input".to_vec()),
            timeout_ms: 5000,
            cwd: None,
        };
        let payload = encode_frame_payload(&frame).unwrap();
        assert!(payload.starts_with(EXEC_DM_PREFIX));
        let decoded = decode_frame_payload(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_started_frame() {
        let frame = ExecFrame::Started {
            request_id: test_request_id(),
            pid: 12345,
        };
        let payload = encode_frame_payload(&frame).unwrap();
        let decoded = decode_frame_payload(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_stdout_stderr_frames() {
        let stdout_frame = ExecFrame::Stdout {
            request_id: test_request_id(),
            seq: 0,
            data: b"hello world".to_vec(),
        };
        let stderr_frame = ExecFrame::Stderr {
            request_id: test_request_id(),
            seq: 1,
            data: b"error msg".to_vec(),
        };
        for frame in [stdout_frame, stderr_frame] {
            let payload = encode_frame_payload(&frame).unwrap();
            let decoded = decode_frame_payload(&payload).unwrap();
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn encode_decode_exit_frame_with_denial() {
        let frame = ExecFrame::Exit {
            request_id: test_request_id(),
            code: Some(1),
            signal: None,
            duration_ms: 42,
            stdout_bytes_total: 100,
            stderr_bytes_total: 50,
            truncated: false,
            denial_reason: Some(DenialReason::ArgvNotAllowed),
        };
        let payload = encode_frame_payload(&frame).unwrap();
        let decoded = decode_frame_payload(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_exit_frame_with_signal() {
        let frame = ExecFrame::Exit {
            request_id: test_request_id(),
            code: None,
            signal: Some(9),
            duration_ms: 1000,
            stdout_bytes_total: 0,
            stderr_bytes_total: 0,
            truncated: false,
            denial_reason: None,
        };
        let payload = encode_frame_payload(&frame).unwrap();
        let decoded = decode_frame_payload(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_cancel_and_lease_renew() {
        let rid = test_request_id();
        let cancel = ExecFrame::Cancel { request_id: rid };
        let renew = ExecFrame::LeaseRenew { request_id: rid };
        for frame in [cancel, renew] {
            let payload = encode_frame_payload(&frame).unwrap();
            let decoded = decode_frame_payload(&payload).unwrap();
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn encode_decode_warning_frame() {
        let frame = ExecFrame::Warning {
            request_id: test_request_id(),
            kind: WarningKind::StdoutCapHit,
            message: "stdout output cap reached".to_string(),
        };
        let payload = encode_frame_payload(&frame).unwrap();
        let decoded = decode_frame_payload(&payload).unwrap();
        assert_eq!(decoded, frame);
    }

    // ── Decode rejection tests ────────────────────────────────────────

    #[test]
    fn decode_rejects_missing_prefix() {
        let payload = b"not-an-exec-frame";
        let err = decode_frame_payload(payload).unwrap_err();
        assert!(matches!(err, ProtocolError::MissingPrefix));
    }

    #[test]
    fn decode_rejects_wrong_prefix() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"x0x-exec-v2\0"); // wrong version
        payload.extend_from_slice(&bincode::serialize(&ExecFrame::Cancel { request_id: test_request_id() }).unwrap());
        let err = decode_frame_payload(&payload).unwrap_err();
        assert!(matches!(err, ProtocolError::MissingPrefix));
    }

    #[test]
    fn decode_rejects_truncated_frame() {
        let mut payload = Vec::new();
        payload.extend_from_slice(EXEC_DM_PREFIX);
        payload.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // garbage, too short
        let err = decode_frame_payload(&payload).unwrap_err();
        assert!(matches!(err, ProtocolError::Decode(_)));
    }

    #[test]
    fn decode_rejects_empty_after_prefix() {
        let payload: &[u8] = EXEC_DM_PREFIX;
        let err = decode_frame_payload(payload).unwrap_err();
        assert!(matches!(err, ProtocolError::Decode(_)));
    }

    #[test]
    fn decode_rejects_empty_payload() {
        let err = decode_frame_payload(&[]).unwrap_err();
        assert!(matches!(err, ProtocolError::MissingPrefix));
    }

    // ── WarningKind / DenialReason as_str stability ───────────────────

    #[test]
    fn warning_kind_as_str_is_snake_case() {
        for kind in [
            WarningKind::StdoutCapHit,
            WarningKind::StderrCapHit,
            WarningKind::DurationApproachingCap,
            WarningKind::StdoutApproachingCap,
            WarningKind::StderrApproachingCap,
            WarningKind::LeaseExpired,
            WarningKind::PeerDisconnected,
            WarningKind::Cancelled,
        ] {
            let s = kind.as_str();
            assert!(!s.is_empty());
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn denial_reason_as_str_is_snake_case() {
        for reason in [
            DenialReason::ExecDisabled,
            DenialReason::UnverifiedSender,
            DenialReason::TrustRejected,
            DenialReason::AgentMachineNotInAcl,
            DenialReason::ArgvNotAllowed,
            DenialReason::StdinTooLarge,
            DenialReason::TimeoutTooLarge,
            DenialReason::CwdNotAllowed,
            DenialReason::ConcurrencyLimitReached,
            DenialReason::ShellMetacharInArgv,
            DenialReason::SpawnFailed,
            DenialReason::MalformedFrame,
        ] {
            let s = reason.as_str();
            assert!(!s.is_empty());
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    // ── ExecRunResult round-trip ──────────────────────────────────────

    #[test]
    fn exec_run_result_serialization_roundtrip() {
        let result = ExecRunResult {
            request_id: test_request_id(),
            code: Some(0),
            signal: None,
            duration_ms: 150,
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            stdout_bytes_total: 2,
            stderr_bytes_total: 0,
            truncated: false,
            denial_reason: None,
            warnings: vec![WarningKind::DurationApproachingCap],
        };
        let serialized = bincode::serialize(&result).unwrap();
        let deserialized: ExecRunResult = bincode::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, result);
    }

    // ── Prefix constant sanity ────────────────────────────────────────

    #[test]
    fn exec_dm_prefix_ends_with_null_byte() {
        assert_eq!(EXEC_DM_PREFIX.last(), Some(&b'\0'));
    }

    #[test]
    fn exec_dm_prefix_is_ascii() {
        assert!(EXEC_DM_PREFIX.iter().all(|b| b.is_ascii()));
    }
}
