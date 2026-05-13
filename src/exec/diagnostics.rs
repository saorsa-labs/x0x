//! Diagnostics counters for Tier-1 exec.

use super::acl::AclSummary;
use super::protocol::{DenialReason, ExecRequestId, WarningKind};
use crate::identity::AgentId;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const RECENT_WARNING_LIMIT: usize = 64;

/// Thread-safe exec diagnostics.
pub struct ExecDiagnostics {
    requests_received: AtomicU64,
    requests_allowed: AtomicU64,
    requests_denied: AtomicU64,
    sessions_started: AtomicU64,
    sessions_completed: AtomicU64,
    sessions_cancelled: AtomicU64,
    audit_write_failures: AtomicU64,
    denial_breakdown: Mutex<HashMap<DenialReason, u64>>,
    cap_breaches: Mutex<HashMap<&'static str, u64>>,
    cap_warnings: Mutex<HashMap<WarningKind, u64>>,
    recent_warnings: Mutex<VecDeque<ExecWarningEvent>>,
    acl_summary: AclSummary,
}

impl ExecDiagnostics {
    /// Create diagnostics seeded with a safe ACL summary.
    #[must_use]
    pub fn new(acl_summary: AclSummary) -> Self {
        Self {
            requests_received: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_denied: AtomicU64::new(0),
            sessions_started: AtomicU64::new(0),
            sessions_completed: AtomicU64::new(0),
            sessions_cancelled: AtomicU64::new(0),
            audit_write_failures: AtomicU64::new(0),
            denial_breakdown: Mutex::new(HashMap::new()),
            cap_breaches: Mutex::new(HashMap::new()),
            cap_warnings: Mutex::new(HashMap::new()),
            recent_warnings: Mutex::new(VecDeque::new()),
            acl_summary,
        }
    }

    pub fn record_request_received(&self) {
        self.requests_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_allowed(&self) {
        self.requests_allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_denied(&self, reason: DenialReason) {
        self.requests_denied.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut map) = self.denial_breakdown.lock() {
            *map.entry(reason).or_insert(0) += 1;
        }
    }

    pub fn record_started(&self) {
        self.sessions_started.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_completed(&self) {
        self.sessions_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cancelled(&self) {
        self.sessions_cancelled.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_audit_failure(&self) {
        self.audit_write_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cap_breach(&self, stream: &'static str) {
        if let Ok(mut map) = self.cap_breaches.lock() {
            *map.entry(stream).or_insert(0) += 1;
        }
    }

    pub fn record_warning(
        &self,
        kind: WarningKind,
        agent_id: AgentId,
        request_id: ExecRequestId,
        argv_summary: String,
        bytes_at_warn: Option<u64>,
    ) {
        if let Ok(mut map) = self.cap_warnings.lock() {
            *map.entry(kind).or_insert(0) += 1;
        }
        if let Ok(mut recent) = self.recent_warnings.lock() {
            if recent.len() >= RECENT_WARNING_LIMIT {
                recent.pop_front();
            }
            recent.push_back(ExecWarningEvent {
                ts_unix_ms: now_unix_ms(),
                kind: kind.as_str().to_string(),
                agent_id: hex::encode(agent_id.as_bytes()),
                request_id: request_id.to_hex(),
                argv_summary,
                bytes_at_warn,
            });
        }
    }

    /// Snapshot for `/diagnostics/exec`.
    #[must_use]
    pub fn snapshot(
        &self,
        enabled: bool,
        active_sessions: usize,
        active_per_agent: HashMap<String, usize>,
    ) -> ExecDiagnosticsSnapshot {
        let denial_breakdown = self
            .denial_breakdown
            .lock()
            .map(|map| {
                map.iter()
                    .map(|(k, v)| (k.as_str().to_string(), *v))
                    .collect()
            })
            .unwrap_or_default();
        let cap_breaches = self
            .cap_breaches
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let cap_warnings = self
            .cap_warnings
            .lock()
            .map(|map| {
                map.iter()
                    .map(|(k, v)| (k.as_str().to_string(), *v))
                    .collect()
            })
            .unwrap_or_default();
        let recent_warnings = self
            .recent_warnings
            .lock()
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default();

        ExecDiagnosticsSnapshot {
            ok: true,
            enabled,
            active_sessions,
            active_per_agent,
            totals: ExecTotalsSnapshot {
                requests_received: self.requests_received.load(Ordering::Relaxed),
                requests_allowed: self.requests_allowed.load(Ordering::Relaxed),
                requests_denied: self.requests_denied.load(Ordering::Relaxed),
                sessions_started: self.sessions_started.load(Ordering::Relaxed),
                sessions_completed: self.sessions_completed.load(Ordering::Relaxed),
                sessions_cancelled: self.sessions_cancelled.load(Ordering::Relaxed),
                audit_write_failures: self.audit_write_failures.load(Ordering::Relaxed),
                denial_breakdown,
                cap_breaches,
                cap_warnings,
            },
            recent_warnings,
            acl_summary: self.acl_summary.clone(),
        }
    }
}

/// JSON diagnostics snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ExecDiagnosticsSnapshot {
    pub ok: bool,
    pub enabled: bool,
    pub active_sessions: usize,
    pub active_per_agent: HashMap<String, usize>,
    pub totals: ExecTotalsSnapshot,
    pub recent_warnings: Vec<ExecWarningEvent>,
    pub acl_summary: AclSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecTotalsSnapshot {
    pub requests_received: u64,
    pub requests_allowed: u64,
    pub requests_denied: u64,
    pub sessions_started: u64,
    pub sessions_completed: u64,
    pub sessions_cancelled: u64,
    pub audit_write_failures: u64,
    pub denial_breakdown: HashMap<String, u64>,
    pub cap_breaches: HashMap<&'static str, u64>,
    pub cap_warnings: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecWarningEvent {
    pub ts_unix_ms: u64,
    pub kind: String,
    pub agent_id: String,
    pub request_id: String,
    pub argv_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_at_warn: Option<u64>,
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::acl::AclSummary;
    use crate::exec::protocol::{DenialReason, ExecRequestId, WarningKind};
    use crate::identity::AgentId;

    fn test_acl_summary() -> AclSummary {
        AclSummary {
            enabled: true,
            loaded_from: "/test/acl.toml".to_string(),
            loaded_at_unix_ms: 100,
            allow_entry_count: 5,
            command_entry_count: 10,
            disabled_reason: None,
        }
    }

    fn test_agent_id() -> AgentId {
        AgentId([0xCC; 32])
    }

    fn test_request_id() -> ExecRequestId {
        ExecRequestId([2u8; 16])
    }

    #[test]
    fn diagnostics_new_initializes_counts_to_zero() {
        let d = ExecDiagnostics::new(test_acl_summary());
        let snap = d.snapshot(true, 0, HashMap::new());
        assert!(snap.ok);
        assert!(snap.enabled);
        assert_eq!(snap.active_sessions, 0);
        assert_eq!(snap.totals.requests_received, 0);
        assert_eq!(snap.totals.requests_allowed, 0);
        assert_eq!(snap.totals.requests_denied, 0);
        assert_eq!(snap.totals.sessions_started, 0);
        assert_eq!(snap.totals.sessions_completed, 0);
        assert_eq!(snap.totals.sessions_cancelled, 0);
        assert_eq!(snap.totals.audit_write_failures, 0);
    }

    #[test]
    fn diagnostics_records_request_received() {
        let d = ExecDiagnostics::new(test_acl_summary());
        d.record_request_received();
        d.record_request_received();
        d.record_request_received();
        let snap = d.snapshot(true, 0, HashMap::new());
        assert_eq!(snap.totals.requests_received, 3);
    }

    #[test]
    fn diagnostics_records_allowed_and_denied() {
        let d = ExecDiagnostics::new(test_acl_summary());
        d.record_allowed();
        d.record_allowed();
        d.record_denied(DenialReason::ArgvNotAllowed);
        d.record_denied(DenialReason::ExecDisabled);
        let snap = d.snapshot(true, 0, HashMap::new());
        assert_eq!(snap.totals.requests_allowed, 2);
        assert_eq!(snap.totals.requests_denied, 2);
        assert!(snap
            .totals
            .denial_breakdown
            .contains_key("argv_not_allowed"));
        assert!(snap.totals.denial_breakdown.contains_key("exec_disabled"));
    }

    #[test]
    fn diagnostics_records_session_lifecycle() {
        let d = ExecDiagnostics::new(test_acl_summary());
        d.record_started();
        d.record_started();
        d.record_completed();
        d.record_cancelled();
        let snap = d.snapshot(true, 0, HashMap::new());
        assert_eq!(snap.totals.sessions_started, 2);
        assert_eq!(snap.totals.sessions_completed, 1);
        assert_eq!(snap.totals.sessions_cancelled, 1);
    }

    #[test]
    fn diagnostics_records_audit_failure() {
        let d = ExecDiagnostics::new(test_acl_summary());
        d.record_audit_failure();
        let snap = d.snapshot(true, 0, HashMap::new());
        assert_eq!(snap.totals.audit_write_failures, 1);
    }

    #[test]
    fn diagnostics_records_cap_breach() {
        let d = ExecDiagnostics::new(test_acl_summary());
        d.record_cap_breach("stdout");
        d.record_cap_breach("stdout");
        d.record_cap_breach("stderr");
        let snap = d.snapshot(true, 0, HashMap::new());
        assert_eq!(snap.totals.cap_breaches.get("stdout"), Some(&2u64));
        assert_eq!(snap.totals.cap_breaches.get("stderr"), Some(&1u64));
    }

    #[test]
    fn diagnostics_records_warning() {
        let d = ExecDiagnostics::new(test_acl_summary());
        d.record_warning(
            WarningKind::StdoutCapHit,
            test_agent_id(),
            test_request_id(),
            "cat large.log".to_string(),
            Some(16_777_216),
        );
        let snap = d.snapshot(true, 0, HashMap::new());
        assert_eq!(snap.totals.cap_warnings.get("stdout_cap_hit"), Some(&1u64));
        assert_eq!(snap.recent_warnings.len(), 1);
        assert_eq!(snap.recent_warnings[0].argv_summary, "cat large.log");
    }

    #[test]
    fn diagnostics_snapshot_includes_active_sessions() {
        let d = ExecDiagnostics::new(test_acl_summary());
        let mut per_agent = HashMap::new();
        per_agent.insert("agent1".to_string(), 3usize);
        let snap = d.snapshot(true, 5, per_agent);
        assert_eq!(snap.active_sessions, 5);
        assert_eq!(snap.active_per_agent.get("agent1"), Some(&3usize));
    }

    #[test]
    fn diagnostics_snapshot_shows_disabled() {
        let d = ExecDiagnostics::new(test_acl_summary());
        let snap = d.snapshot(false, 0, HashMap::new());
        assert!(!snap.enabled);
    }

    #[test]
    fn diagnostics_warning_limit_respected() {
        let d = ExecDiagnostics::new(test_acl_summary());
        // Add more than the limit
        for i in 0..70 {
            d.record_warning(
                WarningKind::StdoutCapHit,
                test_agent_id(),
                ExecRequestId([i as u8; 16]),
                format!("cmd-{i}"),
                None,
            );
        }
        let snap = d.snapshot(true, 0, HashMap::new());
        assert_eq!(snap.recent_warnings.len(), 64); // RECENT_WARNING_LIMIT
                                                    // Should have the most recent entries
        assert!(snap
            .recent_warnings
            .last()
            .unwrap()
            .argv_summary
            .contains("cmd-69"));
    }
}
