//! Secure Tier-1 remote exec over signed/encrypted gossip DM.
//!
//! This module deliberately implements a constrained, non-interactive exec
//! primitive.  It is not an SSH replacement: commands are matched against a
//! restart-loaded argv allowlist, no shell is ever invoked, and requesters are
//! gated by the signed x0x `(AgentId, MachineId)` identity pair.

pub mod acl;
pub mod audit;
pub mod diagnostics;
pub mod protocol;
pub mod service;

pub use acl::{default_exec_acl_path, load_exec_policy, ExecAcl, ExecPolicy, LoadMode};
pub use diagnostics::{ExecDiagnostics, ExecDiagnosticsSnapshot};
pub use protocol::{
    decode_frame_payload, encode_frame_payload, DenialReason, ExecFrame, ExecRequestId,
    ExecRunResult, StreamKind, WarningKind, EXEC_DM_PREFIX,
};
pub use service::{ExecRunOptions, ExecService};
