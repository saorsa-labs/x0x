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
