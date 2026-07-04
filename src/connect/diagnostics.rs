//! Connect diagnostics — counter surface for connect allow/deny decisions.
//!
//! Minimal-scope mirror of `exec/diagnostics.rs`. Counters read `0` until T4
//! (issue #132) wires calls to [`ConnectDiagnostics::record_allowed`] /
//! [`record_denied`](ConnectDiagnostics::record_denied); that is the intended
//! "counter surface for future connect denials". v1 has no warnings/sessions
//! machinery — that is T4.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

use crate::connect::acl::ConnectAclSummary;
use crate::connect::gate::ConnectDenialReason;

/// Atomic allow/deny counters + per-reason denial breakdown.
#[derive(Debug)]
pub struct ConnectDiagnostics {
    streams_allowed: std::sync::atomic::AtomicU64,
    streams_denied: std::sync::atomic::AtomicU64,
    denial_breakdown: Mutex<HashMap<ConnectDenialReason, u64>>,
    acl_summary: ConnectAclSummary,
}

impl ConnectDiagnostics {
    /// Construct from the loaded policy's summary.
    #[must_use]
    pub fn new(summary: ConnectAclSummary) -> Self {
        Self {
            streams_allowed: std::sync::atomic::AtomicU64::new(0),
            streams_denied: std::sync::atomic::AtomicU64::new(0),
            denial_breakdown: Mutex::new(HashMap::new()),
            acl_summary: summary,
        }
    }

    /// Record an allowed connect stream.
    pub fn record_allowed(&self) {
        self.streams_allowed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a denied connect stream, bucketed by reason.
    pub fn record_denied(&self, reason: ConnectDenialReason) {
        self.streams_denied
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut map) = self.denial_breakdown.lock() {
            *map.entry(reason).or_insert(0) += 1;
        }
    }

    /// Snapshot for the `/diagnostics/connect` endpoint.
    #[must_use]
    pub fn snapshot(&self) -> ConnectDiagnosticsSnapshot {
        let allowed = self
            .streams_allowed
            .load(std::sync::atomic::Ordering::Relaxed);
        let denied = self
            .streams_denied
            .load(std::sync::atomic::Ordering::Relaxed);
        let breakdown = self
            .denial_breakdown
            .lock()
            .map(|m| m.iter().map(|(k, v)| (*k, *v)).collect())
            .unwrap_or_default();
        ConnectDiagnosticsSnapshot {
            streams_allowed: allowed,
            streams_denied: denied,
            denial_breakdown: breakdown,
            acl_summary: self.acl_summary.clone(),
        }
    }
}

/// Serializable diagnostics snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectDiagnosticsSnapshot {
    pub streams_allowed: u64,
    pub streams_denied: u64,
    pub denial_breakdown: HashMap<ConnectDenialReason, u64>,
    pub acl_summary: ConnectAclSummary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_allowed_and_denied_updates_counters_and_breakdown() {
        let diag = ConnectDiagnostics::new(ConnectAclSummary {
            enabled: true,
            loaded_from: "/tmp/x.toml".to_string(),
            loaded_at_unix_ms: 0,
            allow_entry_count: 1,
            target_entry_count: 1,
            disabled_reason: None,
        });
        diag.record_allowed();
        diag.record_allowed();
        diag.record_denied(ConnectDenialReason::ConnectDisabled);
        diag.record_denied(ConnectDenialReason::TargetNotAllowed);

        let snap = diag.snapshot();
        assert_eq!(snap.streams_allowed, 2);
        assert_eq!(snap.streams_denied, 2);
        assert_eq!(
            snap.denial_breakdown
                .get(&ConnectDenialReason::ConnectDisabled),
            Some(&1)
        );
        assert_eq!(
            snap.denial_breakdown
                .get(&ConnectDenialReason::TargetNotAllowed),
            Some(&1)
        );
        assert!(snap.acl_summary.enabled);
    }
}
