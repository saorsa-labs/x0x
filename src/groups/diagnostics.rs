//! Per-group ingest diagnostics for `/diagnostics/groups`.
//!
//! Mirrors the `/diagnostics/dm` and `/diagnostics/exec` shapes: a small
//! atomic-counter table keyed by stable group id, plus a snapshot helper
//! that joins the counters with the daemon's live `members_v2` /
//! subscription view to produce the JSON returned by the API.
//!
//! The counter set is tuned to surface the
//! `WritePolicyViolation { MembersOnly }` cascade described in
//! `docs/design/groups-join-roster-propagation.md`: every public-message
//! ingest path bumps either `messages_received` (success) or one of the
//! per-reason `messages_dropped_*` buckets, so an operator can see the
//! drop fingerprint without flipping `RUST_LOG=debug` on the daemon.
//!
//! All mutator methods take `&self`; counters are guarded by a single
//! `Mutex` because the contention is per-group and bounded by the
//! gossip ingest rate (orders of magnitude below the lock's saturation
//! point). If profiling later flags this lock, the inner table can be
//! sharded without changing the public API.

use crate::groups::GroupInfo;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Per-group counters captured by the public-message and metadata ingest
/// pipelines. Plain `u64`s — atomic ordering is not required because the
/// outer `Mutex` already serialises updates and snapshot reads.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupCounters {
    /// Validated public messages accepted into the local cache.
    pub messages_received: u64,
    /// Public messages that failed JSON decode.
    pub messages_dropped_decode_failed: u64,
    /// Public messages whose author is currently `Banned`.
    pub messages_dropped_author_banned: u64,
    /// Public messages rejected by `validate_public_message` for write-access
    /// policy reasons (e.g. `MembersOnly` author not in `members_v2`).
    pub messages_dropped_write_policy_violation: u64,
    /// Public messages whose author signature failed to verify, or whose
    /// `author_agent_id` did not match the derived AgentId.
    pub messages_dropped_signature_failed: u64,
    /// Other ingest failures (e.g. `GroupIdMismatch`,
    /// `ConfidentialityMismatch`, `MessageTooLarge`).
    pub messages_dropped_other: u64,
    /// Unix-millis timestamp of the most-recent successful ingest.
    pub last_message_at_ms: Option<u64>,
    /// Number of `MemberJoined` metadata events applied to this group.
    pub member_joined_events_applied: u64,
}

/// Public snapshot of all known groups, returned by `GET /diagnostics/groups`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupsDiagnosticsSnapshot {
    /// One row per locally-known group. Sorted by `group_id` for stable
    /// human-readable output.
    pub groups: Vec<GroupDiagnostic>,
}

/// One row in the diagnostics response.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupDiagnostic {
    /// Stable group id (hex). Matches the key under
    /// `state.named_groups` and the topic-suffix used by gossip.
    pub group_id: String,
    /// Number of active members in the local `members_v2` view.
    pub members_v2_size: usize,
    /// True iff the daemon has a live metadata listener for this group.
    pub subscribed_metadata: bool,
    /// True iff the daemon has a live public-message listener for this
    /// group (false for `MlsEncrypted` groups by design).
    pub subscribed_public: bool,
    /// Inline counter projection.
    #[serde(flatten)]
    pub counters: GroupCounters,
}

/// Process-wide diagnostics table, owned by `AppState`.
#[derive(Debug, Default)]
pub struct GroupsDiagnostics {
    inner: Mutex<HashMap<String, GroupCounters>>,
}

impl GroupsDiagnostics {
    /// Construct an empty diagnostics table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with_counters<F>(&self, group_id: &str, f: F)
    where
        F: FnOnce(&mut GroupCounters),
    {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard.entry(group_id.to_string()).or_default();
        f(entry);
    }

    /// Record a successfully validated public message. `now_ms` is the wall-
    /// clock timestamp the caller already has from `now_millis_u64()`.
    pub fn record_message_received(&self, group_id: &str, now_ms: u64) {
        self.with_counters(group_id, |c| {
            c.messages_received = c.messages_received.saturating_add(1);
            c.last_message_at_ms = Some(now_ms);
        });
    }

    /// Record a JSON decode failure on the public-message topic.
    pub fn record_decode_failed(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.messages_dropped_decode_failed = c.messages_dropped_decode_failed.saturating_add(1);
        });
    }

    /// Record an `AuthorBanned` rejection.
    pub fn record_author_banned(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.messages_dropped_author_banned = c.messages_dropped_author_banned.saturating_add(1);
        });
    }

    /// Record a `WritePolicyViolation` rejection — the headline counter for
    /// the join-roster-propagation regression: a sudden jump on the owner
    /// side immediately after a joiner posts means the owner's
    /// `members_v2` has not converged yet.
    pub fn record_write_policy_violation(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.messages_dropped_write_policy_violation =
                c.messages_dropped_write_policy_violation.saturating_add(1);
        });
    }

    /// Record an `InvalidSignature` rejection.
    pub fn record_signature_failed(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.messages_dropped_signature_failed =
                c.messages_dropped_signature_failed.saturating_add(1);
        });
    }

    /// Record any other ingest failure (size, group_id mismatch,
    /// confidentiality mismatch, etc).
    pub fn record_other_drop(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.messages_dropped_other = c.messages_dropped_other.saturating_add(1);
        });
    }

    /// Record a successful application of a `MemberJoined` metadata event.
    pub fn record_member_joined(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.member_joined_events_applied = c.member_joined_events_applied.saturating_add(1);
        });
    }

    /// Build a snapshot for `GET /diagnostics/groups`. Joins the live
    /// per-group counters with the caller-supplied `members_v2` and
    /// subscription views (the daemon already holds those locks higher up
    /// the call stack, so we keep this function pure-sync).
    #[must_use]
    pub fn snapshot(
        &self,
        groups: &HashMap<String, GroupInfo>,
        metadata_subscribed: &HashSet<String>,
        public_subscribed: &HashSet<String>,
    ) -> GroupsDiagnosticsSnapshot {
        let counters_guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        fn merge_counters(dst: &mut GroupCounters, src: &GroupCounters) {
            dst.messages_received = dst.messages_received.saturating_add(src.messages_received);
            dst.messages_dropped_decode_failed = dst
                .messages_dropped_decode_failed
                .saturating_add(src.messages_dropped_decode_failed);
            dst.messages_dropped_author_banned = dst
                .messages_dropped_author_banned
                .saturating_add(src.messages_dropped_author_banned);
            dst.messages_dropped_write_policy_violation = dst
                .messages_dropped_write_policy_violation
                .saturating_add(src.messages_dropped_write_policy_violation);
            dst.messages_dropped_signature_failed = dst
                .messages_dropped_signature_failed
                .saturating_add(src.messages_dropped_signature_failed);
            dst.messages_dropped_other = dst
                .messages_dropped_other
                .saturating_add(src.messages_dropped_other);
            dst.member_joined_events_applied = dst
                .member_joined_events_applied
                .saturating_add(src.member_joined_events_applied);
            dst.last_message_at_ms = match (dst.last_message_at_ms, src.last_message_at_ms) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (None, Some(b)) => Some(b),
                (a, None) => a,
            };
        }

        let stable_for_key = |key: &str| -> String {
            groups
                .get(key)
                .map(|info| info.stable_group_id().to_string())
                .or_else(|| {
                    groups
                        .values()
                        .find(|info| info.stable_group_id() == key)
                        .map(|info| info.stable_group_id().to_string())
                })
                .unwrap_or_else(|| key.to_string())
        };

        let mut rows: std::collections::BTreeMap<String, GroupDiagnostic> =
            std::collections::BTreeMap::new();
        for (key, info) in groups {
            let stable_id = info.stable_group_id().to_string();
            rows.entry(stable_id.clone())
                .or_insert_with(|| GroupDiagnostic {
                    group_id: stable_id.clone(),
                    members_v2_size: info.members_v2.values().filter(|m| m.is_active()).count(),
                    subscribed_metadata: metadata_subscribed.contains(key)
                        || metadata_subscribed.contains(&stable_id),
                    subscribed_public: public_subscribed.contains(&stable_id)
                        || public_subscribed.contains(key),
                    counters: GroupCounters::default(),
                });
        }

        for (key, counters) in counters_guard.iter() {
            let stable_id = stable_for_key(key);
            let row = rows
                .entry(stable_id.clone())
                .or_insert_with(|| GroupDiagnostic {
                    group_id: stable_id,
                    members_v2_size: 0,
                    subscribed_metadata: metadata_subscribed.contains(key),
                    subscribed_public: public_subscribed.contains(key),
                    counters: GroupCounters::default(),
                });
            merge_counters(&mut row.counters, counters);
        }

        GroupsDiagnosticsSnapshot {
            groups: rows.into_values().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::{GroupInfo, GroupPolicyPreset};
    use crate::identity::AgentId;

    fn group(name: &str, mls_id: &str) -> GroupInfo {
        GroupInfo::with_policy(
            name.to_string(),
            String::new(),
            AgentId([7; 32]),
            mls_id.to_string(),
            GroupPolicyPreset::PublicOpen.to_policy(),
        )
    }

    #[test]
    fn record_and_snapshot_isolates_counters_per_group() {
        let diag = GroupsDiagnostics::new();
        diag.record_message_received("g1", 1_000);
        diag.record_message_received("g1", 1_001);
        diag.record_write_policy_violation("g1");
        diag.record_decode_failed("g2");
        diag.record_member_joined("g2");

        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        groups.insert("g1".into(), group("G1", "g1"));
        groups.insert("g2".into(), group("G2", "g2"));
        let mut meta = HashSet::new();
        meta.insert("g1".to_string());
        let mut pub_set = HashSet::new();
        pub_set.insert("g1".to_string());

        let snap = diag.snapshot(&groups, &meta, &pub_set);
        assert_eq!(snap.groups.len(), 2);
        let g1 = snap.groups.iter().find(|g| g.group_id == "g1").unwrap();
        assert_eq!(g1.counters.messages_received, 2);
        assert_eq!(g1.counters.messages_dropped_write_policy_violation, 1);
        assert_eq!(g1.counters.last_message_at_ms, Some(1_001));
        assert!(g1.subscribed_metadata);
        assert!(g1.subscribed_public);
        let g2 = snap.groups.iter().find(|g| g.group_id == "g2").unwrap();
        assert_eq!(g2.counters.messages_dropped_decode_failed, 1);
        assert_eq!(g2.counters.member_joined_events_applied, 1);
        assert!(!g2.subscribed_metadata);
        assert!(!g2.subscribed_public);
    }

    #[test]
    fn snapshot_includes_groups_without_known_info() {
        // Audit case: counters recorded for a group that's no longer in
        // state.named_groups (e.g. owner deleted while listener flushed).
        let diag = GroupsDiagnostics::new();
        diag.record_other_drop("ghost");
        let groups: HashMap<String, GroupInfo> = HashMap::new();
        let snap = diag.snapshot(&groups, &HashSet::new(), &HashSet::new());
        assert_eq!(snap.groups.len(), 1);
        assert_eq!(snap.groups[0].group_id, "ghost");
        assert_eq!(snap.groups[0].members_v2_size, 0);
        assert_eq!(snap.groups[0].counters.messages_dropped_other, 1);
    }
}
