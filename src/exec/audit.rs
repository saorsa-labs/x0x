//! Append-only JSONL audit for Tier-1 exec.

use super::acl::ExecPolicy;
use super::diagnostics::ExecDiagnostics;
use super::protocol::{DenialReason, ExecRequestId, WarningKind};
use crate::identity::{AgentId, MachineId};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

/// File-backed audit logger.  The optional CRDT TaskList mirror is kept as a
/// configuration field for v1.1; local JSONL is authoritative in v1.
#[derive(Clone)]
pub struct ExecAudit {
    path: Option<PathBuf>,
    diagnostics: Arc<ExecDiagnostics>,
    tasklist_id: Option<String>,
}

impl ExecAudit {
    /// Create an audit sink for a loaded policy.
    #[must_use]
    pub fn new(policy: &ExecPolicy, diagnostics: Arc<ExecDiagnostics>) -> Self {
        match policy {
            ExecPolicy::Enabled(acl) => Self {
                path: Some(acl.audit_log_path.clone()),
                diagnostics,
                tasklist_id: acl.audit_tasklist_id.clone(),
            },
            ExecPolicy::Disabled { .. } => Self {
                path: None,
                diagnostics,
                tasklist_id: None,
            },
        }
    }

    /// Configured CRDT audit TaskList id, if any.
    #[must_use]
    pub fn tasklist_id(&self) -> Option<&str> {
        self.tasklist_id.as_deref()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn request(
        &self,
        request_id: ExecRequestId,
        agent_id: AgentId,
        machine_id: MachineId,
        argv: &[String],
        matched_acl: Option<&str>,
        stdin_bytes: usize,
        timeout_ms: u32,
    ) {
        self.write(&AuditEvent::Request {
            ts_unix_ms: now_unix_ms(),
            request_id: request_id.to_hex(),
            agent_id: hex::encode(agent_id.as_bytes()),
            machine_id: hex::encode(machine_id.as_bytes()),
            argv,
            matched_acl,
            stdin_bytes,
            timeout_ms,
        })
        .await;
    }

    pub async fn started(&self, request_id: ExecRequestId, pid: u32) {
        self.write(&AuditEvent::Started {
            ts_unix_ms: now_unix_ms(),
            request_id: request_id.to_hex(),
            pid,
        })
        .await;
    }

    pub async fn warning(&self, request_id: ExecRequestId, kind: WarningKind, bytes: Option<u64>) {
        self.write(&AuditEvent::Warning {
            ts_unix_ms: now_unix_ms(),
            request_id: request_id.to_hex(),
            kind: kind.as_str(),
            bytes,
        })
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn exit(
        &self,
        request_id: ExecRequestId,
        code: Option<i32>,
        signal: Option<i32>,
        duration_ms: u64,
        stdout_bytes: u64,
        stderr_bytes: u64,
        truncated: bool,
    ) {
        self.write(&AuditEvent::Exit {
            ts_unix_ms: now_unix_ms(),
            request_id: request_id.to_hex(),
            code,
            signal,
            duration_ms,
            stdout_bytes,
            stderr_bytes,
            truncated,
        })
        .await;
    }

    pub async fn denial(
        &self,
        request_id: ExecRequestId,
        agent_id: AgentId,
        machine_id: MachineId,
        argv: &[String],
        reason: DenialReason,
    ) {
        self.write(&AuditEvent::Denial {
            ts_unix_ms: now_unix_ms(),
            request_id: request_id.to_hex(),
            agent_id: hex::encode(agent_id.as_bytes()),
            machine_id: hex::encode(machine_id.as_bytes()),
            argv,
            reason: reason.as_str(),
        })
        .await;
    }

    async fn write<T: Serialize + ?Sized>(&self, event: &T) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                tracing::warn!(path = %parent.display(), error = %e, "failed to create exec audit directory");
                self.diagnostics.record_audit_failure();
                return;
            }
        }
        let line = match serde_json::to_vec(event) {
            Ok(mut bytes) => {
                bytes.push(b'\n');
                bytes
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to encode exec audit event");
                self.diagnostics.record_audit_failure();
                return;
            }
        };
        let mut file = match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
        {
            Ok(file) => file,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to open exec audit log");
                self.diagnostics.record_audit_failure();
                return;
            }
        };
        if let Err(e) = file.write_all(&line).await {
            tracing::warn!(path = %path.display(), error = %e, "failed to write exec audit log");
            self.diagnostics.record_audit_failure();
            return;
        }
        if let Err(e) = file.sync_data().await {
            tracing::warn!(path = %path.display(), error = %e, "failed to fsync exec audit log");
            self.diagnostics.record_audit_failure();
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum AuditEvent<'a> {
    Request {
        ts_unix_ms: u64,
        request_id: String,
        agent_id: String,
        machine_id: String,
        argv: &'a [String],
        matched_acl: Option<&'a str>,
        stdin_bytes: usize,
        timeout_ms: u32,
    },
    Started {
        ts_unix_ms: u64,
        request_id: String,
        pid: u32,
    },
    Warning {
        ts_unix_ms: u64,
        request_id: String,
        kind: &'static str,
        bytes: Option<u64>,
    },
    Exit {
        ts_unix_ms: u64,
        request_id: String,
        code: Option<i32>,
        signal: Option<i32>,
        duration_ms: u64,
        stdout_bytes: u64,
        stderr_bytes: u64,
        truncated: bool,
    },
    Denial {
        ts_unix_ms: u64,
        request_id: String,
        agent_id: String,
        machine_id: String,
        argv: &'a [String],
        reason: &'static str,
    },
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(_) => 0,
    }
}
