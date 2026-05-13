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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::exec::acl::{ExecAcl, ExecCaps};
    use crate::exec::protocol::ExecRequestId;
    use crate::identity::{AgentId, MachineId};

    fn test_agent_id() -> AgentId {
        AgentId([0xAA; 32])
    }

    fn test_machine_id() -> MachineId {
        MachineId([0xBB; 32])
    }

    fn test_request_id() -> ExecRequestId {
        ExecRequestId([1u8; 16])
    }

    fn disabled_policy(path: PathBuf) -> ExecPolicy {
        ExecPolicy::Disabled {
            path,
            reason: "test".to_string(),
            loaded_at_unix_ms: 1,
        }
    }

    fn enabled_policy(path: PathBuf) -> ExecPolicy {
        ExecPolicy::Enabled(ExecAcl {
            loaded_from: path.clone(),
            loaded_at_unix_ms: 1,
            caps: ExecCaps::default(),
            audit_log_path: path.join("audit.jsonl"),
            audit_tasklist_id: None,
            allow: vec![],
        })
    }

    #[tokio::test]
    async fn disabled_policy_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let policy = disabled_policy(dir.path().to_path_buf());
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        let audit = ExecAudit::new(&policy, diagnostics);

        assert!(audit.tasklist_id().is_none());

        // These should not panic or create files
        audit
            .request(
                test_request_id(),
                test_agent_id(),
                test_machine_id(),
                &[],
                None,
                0,
                0,
            )
            .await;
        audit.started(test_request_id(), 12345).await;
        audit
            .exit(test_request_id(), Some(0), None, 100, 10, 5, false)
            .await;

        // No audit file should exist
        assert!(!dir.path().join("audit.jsonl").exists());
    }

    #[tokio::test]
    async fn enabled_policy_writes_request_event() {
        let dir = tempfile::tempdir().unwrap();
        let policy = enabled_policy(dir.path().to_path_buf());
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        let audit = ExecAudit::new(&policy, diagnostics);

        audit
            .request(
                test_request_id(),
                test_agent_id(),
                test_machine_id(),
                &["ls".to_string(), "-la".to_string()],
                Some("default"),
                100,
                30000,
            )
            .await;

        let audit_path = dir.path().join("audit.jsonl");
        assert!(audit_path.exists(), "audit file should exist");
        let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
        assert!(content.contains("request"), "should contain request event");
        assert!(content.contains("ls"), "should contain argv");
    }

    #[tokio::test]
    async fn enabled_policy_writes_all_event_types() {
        let dir = tempfile::tempdir().unwrap();
        let policy = enabled_policy(dir.path().to_path_buf());
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        let audit = ExecAudit::new(&policy, diagnostics);

        audit
            .request(
                test_request_id(),
                test_agent_id(),
                test_machine_id(),
                &["echo".to_string()],
                None,
                0,
                5000,
            )
            .await;
        audit.started(test_request_id(), 99999).await;
        audit
            .warning(test_request_id(), WarningKind::StdoutCapHit, Some(1024))
            .await;
        audit
            .exit(test_request_id(), Some(0), None, 200, 50, 10, false)
            .await;

        let audit_path = dir.path().join("audit.jsonl");
        let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 4, "should have 4 events: {content}");
        assert!(lines[0].contains("request"));
        assert!(lines[1].contains("started"));
        assert!(lines[2].contains("warning"));
        assert!(lines[3].contains("exit"));
    }

    #[tokio::test]
    async fn enabled_policy_writes_denial_event() {
        let dir = tempfile::tempdir().unwrap();
        let policy = enabled_policy(dir.path().to_path_buf());
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        let audit = ExecAudit::new(&policy, diagnostics);

        audit
            .denial(
                test_request_id(),
                test_agent_id(),
                test_machine_id(),
                &["rm".to_string(), "-rf".to_string(), "/".to_string()],
                DenialReason::ArgvNotAllowed,
            )
            .await;

        let audit_path = dir.path().join("audit.jsonl");
        let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
        assert!(content.contains("denial"));
        assert!(content.contains("argv_not_allowed"));
        assert!(content.contains("rm"));
    }

    #[tokio::test]
    async fn audit_creates_directory_automatically() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("deep");
        let policy = enabled_policy(nested.clone());
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        let audit = ExecAudit::new(&policy, diagnostics);

        audit
            .request(
                test_request_id(),
                test_agent_id(),
                test_machine_id(),
                &[],
                None,
                0,
                0,
            )
            .await;

        let audit_path = nested.join("audit.jsonl");
        assert!(audit_path.exists(), "nested audit file should exist");
    }

    #[tokio::test]
    async fn multiple_events_append_to_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let policy = enabled_policy(dir.path().to_path_buf());
        let diagnostics = Arc::new(ExecDiagnostics::new(policy.summary()));
        let audit = ExecAudit::new(&policy, diagnostics);

        for i in 0..5 {
            let rid = ExecRequestId([i as u8; 16]);
            audit
                .request(
                    rid,
                    test_agent_id(),
                    test_machine_id(),
                    &[format!("cmd-{i}")],
                    None,
                    0,
                    0,
                )
                .await;
        }

        let audit_path = dir.path().join("audit.jsonl");
        let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        for (i, line) in lines.iter().enumerate().take(5) {
            assert!(line.contains(&format!("cmd-{i}")));
        }
    }

    #[test]
    fn now_unix_ms_returns_reasonable_value() {
        let ts = now_unix_ms();
        // Should be a recent timestamp (after 2020)
        assert!(ts > 1_600_000_000_000, "ts={ts} seems too small");
        // Should not be absurdly large
        assert!(ts < 9_999_999_999_999, "ts={ts} seems too large");
    }
}
