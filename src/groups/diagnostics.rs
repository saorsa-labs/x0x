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
/// #468 A5 (r3): the per-group rate-limit window for
/// [`GroupsDiagnostics::record_conflict_unauthenticated`] — one
/// increment per group per second. Unauthenticated conflict packets are
/// freely replayable; the counter observes conflict PRESSURE, not the
/// attacker's packet rate.
const CONFLICT_UNAUTHENTICATED_WINDOW_MS: u64 = 1_000;

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
    /// This is the ingest (receiver-side) canary for the join-roster-propagation
    /// regression: a non-zero value means joiners' messages are reaching this
    /// node's listener but `members_v2` is stale. See also
    /// `sends_rejected_write_policy` for the sender-side count.
    pub messages_dropped_write_policy_violation: u64,
    /// Outgoing public group sends that were rejected locally by a members-only
    /// write-access policy. A non-zero value means THIS daemon is not present in
    /// its own local roster copy. Tracked separately from
    /// `messages_dropped_write_policy_violation` (the receiver-side ingest
    /// canary) so that operators can distinguish the two failure modes.
    pub sends_rejected_write_policy: u64,
    /// Public-message gossip topic publish completed while at least one
    /// per-member unicast attempt was still in flight (issue #310). A zero
    /// value after a multi-member send means fan-out regressed to
    /// unicast-then-gossip sequence and the receiver will wait out the DM
    /// retry budget (~24s) before the topic carry lands.
    pub public_message_gossip_raced_unicast: u64,
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
    /// Number of `MemberJoined` events rejected because the joiner requested
    /// a role other than the invite-join Member role.
    pub member_joined_events_rejected_non_member_role: u64,
    /// Number of `MemberJoined` events rejected because the invite secret was
    /// not issued by this local inviter.
    pub member_joined_events_rejected_invite_secret_unknown: u64,
    /// #469 A2: v4 joiner-side invite refusals by typed reason
    /// (`invite_unsigned`, `invite_signature_invalid`,
    /// `inviter_key_mismatch|revoked`, `invite_base_inconsistent`,
    /// `invite_owner_countersignature_missing|invalid`,
    /// `invite_not_addressed_to_me`, mode/pin matrix outcomes).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub invites_refused_reasons: std::collections::BTreeMap<String, u64>,
    /// #468 A5: UNIQUE authenticated fork-evidence records adopted into
    /// `invite_lineage` (deduplicated by `(revision, state_hash,
    /// committed_by)`; replays do not increment).
    pub adoption_fork_evidence: u64,
    /// #468 A5: unauthenticated fork CONFLICT attempts (per-packet;
    /// rate-limited to one increment per group per second by
    /// `GroupsDiagnostics::record_conflict_unauthenticated` — an attacker can
    /// replay unauthenticated conflict packets, so the raw count is not
    /// observable; explicitly NOT unique evidence).
    pub conflict_unauthenticated: u64,
    /// #469 D2: members whose certificate bytes have not yet hydrated
    /// from the announce/discovery cache (gauge at snapshot time —
    /// active seats with a committed `certificate_digest` but no
    /// certificate bytes).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub members_awaiting_certificate: u64,
    /// Number of `MemberJoined` events rejected because the joiner's
    /// OwnerCertified certificate evidence had not resolved yet (#447). The
    /// event is retained pending evidence, so this counts retries too.
    pub member_joined_events_rejected_owner_cert_pending: u64,
    /// Number of `MemberJoined` events rejected because the group's TreeKEM
    /// group was unavailable (missing/restored-mismatch) at apply time (#457).
    pub member_joined_events_rejected_treekem_unavailable: u64,
    /// Number of authority `MemberAdded` commits adopted by a joiner stub
    /// whose local chain could not validate the prev hash directly (#458).
    pub member_added_events_adopted: u64,
    /// Number of `MemberAdded` commits rejected on a state-chain gap the
    /// joiner could neither validate nor adopt (#458).
    pub member_added_events_rejected_state_chain_gap: u64,
    // ── ADR 0028 causal predecessor delivery counters ──
    /// Predecessor envelopes relayed to active witnesses.
    pub causal_relayed: u64,
    /// Drain retries attempted.
    pub causal_retried: u64,
    /// Approvals admitted to the causal queue.
    pub causal_queued: u64,
    /// Exact duplicate digests coalesced.
    pub causal_deduplicated: u64,
    /// Queued approvals successfully applied during drain.
    pub causal_applied: u64,
    /// Queue entries expired before their predecessor arrived.
    pub causal_expired: u64,
    /// Entries rejected for failing admission checks.
    pub causal_invalid: u64,
    /// Non-identical conflicts detected (same group/request/requester/revision).
    pub causal_conflicted: u64,
    /// Entries rejected due to count or byte caps.
    pub causal_capacity_rejected: u64,
    /// #482: TreeKEM membership events queued awaiting state-chain
    /// catch-up/replay (the wedge class where a verified event — e.g. a
    /// second device's self-leave — could previously sit queued forever
    /// with no other signal).
    pub membership_events_queued_revision_gap: u64,
}

/// Per-group gauges for ADR 0028 causal predecessor delivery. Populated by the
/// route handler from live queue/outbox state and passed to `snapshot`.
#[derive(Debug, Clone, Default)]
pub struct CausalGauges {
    /// Current causal approval queue depth.
    pub queue_entries: usize,
    /// Current causal approval queue serialized bytes.
    pub queue_bytes: usize,
    /// Current predecessor relay outbox obligations.
    pub relay_obligations: usize,
}

/// Public snapshot of all known groups, returned by `GET /diagnostics/groups`.
fn is_zero(value: &u64) -> bool {
    *value == 0
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
    // ── ADR 0028 causal predecessor delivery gauges ──
    /// Current causal approval queue depth for this group.
    pub causal_queue_entries: usize,
    /// Current causal approval queue serialized bytes for this group.
    pub causal_queue_bytes: usize,
    /// Current predecessor relay outbox obligations for this group.
    pub causal_relay_obligations: usize,
}

/// Process-wide diagnostics table, owned by `AppState`.
#[derive(Debug, Default)]
pub struct GroupsDiagnostics {
    inner: Mutex<HashMap<String, GroupCounters>>,
    /// #468 A5 (r3): identities of fork-evidence records whose
    /// first-observation diagnostics (warn + `adoption_fork_evidence`)
    /// have already fired — post-first observations of the SAME
    /// `(group, revision, state_hash, committed_by)` are silent, even
    /// when the lineage record itself could not be (re)installed (e.g.
    /// a failed persist rolled it back). In-memory only: after a
    /// restart the durable lineage record's own identity dedupe takes
    /// over (see `evaluate_fork_evidence_candidate`).
    seen_fork_evidence: Mutex<HashSet<(String, u64, String, String)>>,
    /// #468 A5 (r3): per-group wall-clock (ms) of the last
    /// `conflict_unauthenticated` increment — unauthenticated conflict
    /// packets are attacker-replayable, so the counter is rate-limited
    /// to one increment per group per second.
    conflict_unauthenticated_last_ms: Mutex<HashMap<String, u64>>,
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

    /// #482: record a TreeKEM membership event queued for state-chain
    /// catch-up/replay.
    pub fn record_membership_event_queued_revision_gap(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.membership_events_queued_revision_gap =
                c.membership_events_queued_revision_gap.saturating_add(1);
        });
    }

    /// #468 A5 (r3): record an unauthenticated conflict attempt.
    /// RATE-LIMITED to one increment per group per
    /// the per-group one-second window (CONFLICT_UNAUTHENTICATED_WINDOW_MS) — the counter observes
    /// that a group is under conflict pressure, not the attacker's
    /// packet rate; unauthenticated conflicts are freely replayable, so
    /// an unbounded count is both useless and a cheap write-amplifier.
    /// `now_ms` is the wall-clock millis the caller already holds
    /// (same contract as [`Self::record_message_received`]).
    pub fn record_conflict_unauthenticated(&self, group_id: &str, now_ms: u64) {
        {
            let mut last = match self.conflict_unauthenticated_last_ms.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let window_start = last
                .get(group_id)
                .copied()
                .unwrap_or(0)
                .saturating_add(CONFLICT_UNAUTHENTICATED_WINDOW_MS);
            if now_ms < window_start {
                return;
            }
            last.insert(group_id.to_string(), now_ms);
        }
        self.with_counters(group_id, |c| {
            c.conflict_unauthenticated = c.conflict_unauthenticated.saturating_add(1);
        });
    }

    /// #468 A5 (r3): fire the first-observation diagnostics for one
    /// fork-evidence identity — `(group, revision, state_hash,
    /// committed_by)` — exactly ONCE per process. Returns `true` only
    /// the first time this identity is observed (incrementing
    /// `adoption_fork_evidence`); every later observation of the same
    /// identity is silent: no counter, no warn (the caller owns the
    /// warn), no re-persist. A DIFFERENT identity for the same group
    /// still fires. The set is in-memory: after a restart, the durable
    /// lineage record's own identity check provides the same silence.
    pub fn record_fork_evidence_once(
        &self,
        group_id: &str,
        revision: u64,
        state_hash: &str,
        committed_by: &str,
    ) -> bool {
        let identity = (
            group_id.to_string(),
            revision,
            state_hash.to_string(),
            committed_by.to_ascii_lowercase(),
        );
        {
            let mut seen = match self.seen_fork_evidence.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if !seen.insert(identity) {
                return false;
            }
        }
        self.with_counters(group_id, |c| {
            c.adoption_fork_evidence = c.adoption_fork_evidence.saturating_add(1);
        });
        true
    }
    /// #469 A2: record a typed invite refusal reason.
    pub fn record_invite_refusal(&self, group_id: &str, reason: &str) {
        self.with_counters(group_id, |c| {
            let entry = c
                .invites_refused_reasons
                .entry(reason.to_string())
                .or_insert(0);
            *entry = entry.saturating_add(1);
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

    /// Record a receiver-side `WritePolicyViolation` rejection — the headline
    /// counter for the join-roster-propagation regression: a sudden jump on
    /// the owner side immediately after a joiner posts means the owner's
    /// `members_v2` has not converged yet.
    ///
    /// Call this on the INGEST path only. For outgoing sends rejected locally
    /// by a members-only policy, use `record_sender_write_policy_rejection`.
    pub fn record_write_policy_violation(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.messages_dropped_write_policy_violation =
                c.messages_dropped_write_policy_violation.saturating_add(1);
        });
    }

    /// Record a sender-side write-policy rejection: this daemon attempted to
    /// send a public group message but was refused because it is not in the
    /// local `members_v2` roster for a members-only group.
    ///
    /// Tracked in a separate field (`sends_rejected_write_policy`) from the
    /// receiver-side ingest counter (`messages_dropped_write_policy_violation`)
    /// so operators can distinguish "I cannot see joiners" from "I am missing
    /// from my own roster".
    pub fn record_sender_write_policy_rejection(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.sends_rejected_write_policy = c.sends_rejected_write_policy.saturating_add(1);
        });
    }

    /// Record that a public-message gossip publish *finished* while unicast
    /// was still in flight. Increment only at that moment — a schedule-time
    /// bump would fire before `publish` runs and would not mean what the
    /// field comment says. A test that only checks eventual delivery cannot
    /// tell a race from a 24s sequential fallback that later succeeded.
    pub fn record_public_message_gossip_raced_unicast(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.public_message_gossip_raced_unicast =
                c.public_message_gossip_raced_unicast.saturating_add(1);
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

    /// Record a `MemberJoined` rejection for a requested role other than Member.
    pub fn record_member_joined_rejected_non_member_role(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.member_joined_events_rejected_non_member_role = c
                .member_joined_events_rejected_non_member_role
                .saturating_add(1);
        });
    }

    /// Record a `MemberJoined` rejection for an unknown invite secret.
    pub fn record_member_joined_rejected_invite_secret_unknown(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.member_joined_events_rejected_invite_secret_unknown = c
                .member_joined_events_rejected_invite_secret_unknown
                .saturating_add(1);
        });
    }
    /// Record a `MemberJoined` rejection pending OwnerCertified certificate
    /// evidence (#447) — the event is retained and retried once evidence
    /// resolves.
    pub fn record_member_joined_rejected_owner_cert_pending(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.member_joined_events_rejected_owner_cert_pending = c
                .member_joined_events_rejected_owner_cert_pending
                .saturating_add(1);
        });
    }

    /// Record a `MemberJoined` rejection because the TreeKEM group was
    /// unavailable at apply time (#457).
    pub fn record_member_joined_rejected_treekem_unavailable(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.member_joined_events_rejected_treekem_unavailable = c
                .member_joined_events_rejected_treekem_unavailable
                .saturating_add(1);
        });
    }

    /// Record a joiner adopting an authority `MemberAdded` commit across a
    /// local state-chain gap (#458).
    pub fn record_member_added_adopted(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.member_added_events_adopted = c.member_added_events_adopted.saturating_add(1);
        });
    }

    /// Record a `MemberAdded` rejection on an unadoptable state-chain gap (#458).
    pub fn record_member_added_rejected_state_chain_gap(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.member_added_events_rejected_state_chain_gap = c
                .member_added_events_rejected_state_chain_gap
                .saturating_add(1);
        });
    }

    // ── ADR 0028 causal predecessor delivery counter methods ──

    /// Record a predecessor envelope relayed to active witnesses.
    pub fn record_causal_relayed(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_relayed = c.causal_relayed.saturating_add(1);
        });
    }

    /// Record a drain retry attempt.
    pub fn record_causal_retried(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_retried = c.causal_retried.saturating_add(1);
        });
    }

    /// Record an approval admitted to the causal queue.
    pub fn record_causal_queued(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_queued = c.causal_queued.saturating_add(1);
        });
    }

    /// Record a coalesced exact-duplicate digest.
    pub fn record_causal_deduplicated(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_deduplicated = c.causal_deduplicated.saturating_add(1);
        });
    }

    /// Record a queued approval successfully applied during drain.
    pub fn record_causal_applied(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_applied = c.causal_applied.saturating_add(1);
        });
    }

    /// Record a queue entry that expired.
    pub fn record_causal_expired(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_expired = c.causal_expired.saturating_add(1);
        });
    }

    /// Record an entry rejected for failing admission checks.
    pub fn record_causal_invalid(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_invalid = c.causal_invalid.saturating_add(1);
        });
    }

    /// Record a non-identical conflict detected.
    pub fn record_causal_conflicted(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_conflicted = c.causal_conflicted.saturating_add(1);
        });
    }

    /// Record an entry rejected due to count or byte caps.
    pub fn record_causal_capacity_rejected(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.causal_capacity_rejected = c.causal_capacity_rejected.saturating_add(1);
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
        causal_gauges: &HashMap<String, CausalGauges>,
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
            for (reason, count) in &src.invites_refused_reasons {
                let entry = dst
                    .invites_refused_reasons
                    .entry(reason.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(*count);
            }
            dst.adoption_fork_evidence = dst
                .adoption_fork_evidence
                .saturating_add(src.adoption_fork_evidence);
            dst.conflict_unauthenticated = dst
                .conflict_unauthenticated
                .saturating_add(src.conflict_unauthenticated);
            dst.messages_dropped_author_banned = dst
                .messages_dropped_author_banned
                .saturating_add(src.messages_dropped_author_banned);
            dst.messages_dropped_write_policy_violation = dst
                .messages_dropped_write_policy_violation
                .saturating_add(src.messages_dropped_write_policy_violation);
            dst.sends_rejected_write_policy = dst
                .sends_rejected_write_policy
                .saturating_add(src.sends_rejected_write_policy);
            dst.public_message_gossip_raced_unicast = dst
                .public_message_gossip_raced_unicast
                .saturating_add(src.public_message_gossip_raced_unicast);
            dst.messages_dropped_signature_failed = dst
                .messages_dropped_signature_failed
                .saturating_add(src.messages_dropped_signature_failed);
            dst.messages_dropped_other = dst
                .messages_dropped_other
                .saturating_add(src.messages_dropped_other);
            dst.member_joined_events_applied = dst
                .member_joined_events_applied
                .saturating_add(src.member_joined_events_applied);
            dst.member_joined_events_rejected_non_member_role = dst
                .member_joined_events_rejected_non_member_role
                .saturating_add(src.member_joined_events_rejected_non_member_role);
            dst.member_joined_events_rejected_invite_secret_unknown = dst
                .member_joined_events_rejected_invite_secret_unknown
                .saturating_add(src.member_joined_events_rejected_invite_secret_unknown);
            dst.member_joined_events_rejected_owner_cert_pending = dst
                .member_joined_events_rejected_owner_cert_pending
                .saturating_add(src.member_joined_events_rejected_owner_cert_pending);
            dst.member_joined_events_rejected_treekem_unavailable = dst
                .member_joined_events_rejected_treekem_unavailable
                .saturating_add(src.member_joined_events_rejected_treekem_unavailable);
            dst.member_added_events_adopted = dst
                .member_added_events_adopted
                .saturating_add(src.member_added_events_adopted);
            dst.member_added_events_rejected_state_chain_gap = dst
                .member_added_events_rejected_state_chain_gap
                .saturating_add(src.member_added_events_rejected_state_chain_gap);
            dst.causal_relayed = dst.causal_relayed.saturating_add(src.causal_relayed);
            dst.causal_retried = dst.causal_retried.saturating_add(src.causal_retried);
            dst.causal_queued = dst.causal_queued.saturating_add(src.causal_queued);
            dst.causal_deduplicated = dst
                .causal_deduplicated
                .saturating_add(src.causal_deduplicated);
            dst.causal_applied = dst.causal_applied.saturating_add(src.causal_applied);
            dst.causal_expired = dst.causal_expired.saturating_add(src.causal_expired);
            dst.causal_invalid = dst.causal_invalid.saturating_add(src.causal_invalid);
            dst.causal_conflicted = dst.causal_conflicted.saturating_add(src.causal_conflicted);
            dst.causal_capacity_rejected = dst
                .causal_capacity_rejected
                .saturating_add(src.causal_capacity_rejected);
            dst.membership_events_queued_revision_gap = dst
                .membership_events_queued_revision_gap
                .saturating_add(src.membership_events_queued_revision_gap);
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
            // r3 (Codex 8): the #469 D2 gauge — active seats whose
            // certificate is digest-only (committed
            // `certificate_digest`, no bytes) are exactly the seats the
            // F1 bridge / seat-time hydrate still owes bytes to.
            let awaiting_certificate = info
                .members_v2
                .values()
                .filter(|m| {
                    m.is_active() && m.certificate.is_none() && m.certificate_digest.is_some()
                })
                .count() as u64;
            rows.entry(stable_id.clone())
                .or_insert_with(|| GroupDiagnostic {
                    group_id: stable_id.clone(),
                    members_v2_size: info.members_v2.values().filter(|m| m.is_active()).count(),
                    subscribed_metadata: metadata_subscribed.contains(key)
                        || metadata_subscribed.contains(&stable_id),
                    subscribed_public: public_subscribed.contains(&stable_id)
                        || public_subscribed.contains(key),
                    counters: GroupCounters {
                        members_awaiting_certificate: awaiting_certificate,
                        ..GroupCounters::default()
                    },
                    causal_queue_entries: causal_gauges
                        .get(key)
                        .or_else(|| causal_gauges.get(&stable_id))
                        .map(|g| g.queue_entries)
                        .unwrap_or(0),
                    causal_queue_bytes: causal_gauges
                        .get(key)
                        .or_else(|| causal_gauges.get(&stable_id))
                        .map(|g| g.queue_bytes)
                        .unwrap_or(0),
                    causal_relay_obligations: causal_gauges
                        .get(key)
                        .or_else(|| causal_gauges.get(&stable_id))
                        .map(|g| g.relay_obligations)
                        .unwrap_or(0),
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
                    causal_queue_entries: 0,
                    causal_queue_bytes: 0,
                    causal_relay_obligations: 0,
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
        diag.record_member_joined_rejected_non_member_role("g2");
        diag.record_member_joined_rejected_invite_secret_unknown("g2");

        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        groups.insert("g1".into(), group("G1", "g1"));
        groups.insert("g2".into(), group("G2", "g2"));
        let mut meta = HashSet::new();
        meta.insert("g1".to_string());
        let mut pub_set = HashSet::new();
        pub_set.insert("g1".to_string());

        let snap = diag.snapshot(&groups, &meta, &pub_set, &HashMap::new());
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
        assert_eq!(g2.counters.member_joined_events_rejected_non_member_role, 1);
        assert_eq!(
            g2.counters
                .member_joined_events_rejected_invite_secret_unknown,
            1
        );
        assert!(!g2.subscribed_metadata);
        assert!(!g2.subscribed_public);
    }

    /// Verify that the receiver-side ingest counter and the sender-side
    /// rejection counter move independently.
    ///
    /// Before the fix the sender-side rejection incremented
    /// `messages_dropped_write_policy_violation` (the same field as the
    /// receiver-side ingest counter), destroying its meaning as the
    /// join-roster-propagation canary. After the fix the two fields are
    /// distinct: an ingest drop bumps `messages_dropped_write_policy_violation`
    /// while a local send rejection bumps `sends_rejected_write_policy`.
    ///
    /// If the sender-side call is changed back to
    /// `record_write_policy_violation`, the `sends_rejected_write_policy`
    /// assertion fails (stays 0) and the `messages_dropped_write_policy_violation`
    /// assertion also fails (becomes 2 instead of 1).
    #[test]
    fn sender_and_receiver_write_policy_counters_are_independent() {
        let diag = GroupsDiagnostics::new();

        // Receiver-side: ingest path dropped an incoming message.
        diag.record_write_policy_violation("grp");
        // Sender-side: this daemon's own outgoing send was rejected locally.
        diag.record_sender_write_policy_rejection("grp");

        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        groups.insert("grp".into(), group("Grp", "grp"));
        let snap = diag.snapshot(&groups, &HashSet::new(), &HashSet::new(), &HashMap::new());

        let g = snap.groups.iter().find(|g| g.group_id == "grp").unwrap();
        assert_eq!(
            g.counters.messages_dropped_write_policy_violation, 1,
            "receiver-side ingest drop must be in messages_dropped_write_policy_violation only"
        );
        assert_eq!(
            g.counters.sends_rejected_write_policy, 1,
            "sender-side local rejection must be in sends_rejected_write_policy only"
        );
    }

    /// Why: a sequential unicast-then-gossip fan-out can still deliver, so a
    /// delivery assertion alone cannot catch issue #310. The raced counter is
    /// the signal that topic publish finished while DM unicast was still
    /// outstanding — if this method is wired to the wrong field, the
    /// two-daemon <5s test would pass for the wrong reason.
    #[test]
    fn gossip_raced_unicast_counter_is_independent() {
        let diag = GroupsDiagnostics::new();
        diag.record_message_received("grp", 1);
        diag.record_public_message_gossip_raced_unicast("grp");
        diag.record_public_message_gossip_raced_unicast("grp");

        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        groups.insert("grp".into(), group("Grp", "grp"));
        let snap = diag.snapshot(&groups, &HashSet::new(), &HashSet::new(), &HashMap::new());
        let g = snap.groups.iter().find(|g| g.group_id == "grp").unwrap();
        assert_eq!(g.counters.messages_received, 1);
        assert_eq!(
            g.counters.public_message_gossip_raced_unicast, 2,
            "raced-unicast counter must not alias messages_received"
        );
    }

    #[test]
    fn snapshot_includes_groups_without_known_info() {
        // Audit case: counters recorded for a group that's no longer in
        // state.named_groups (e.g. owner deleted while listener flushed).
        let diag = GroupsDiagnostics::new();
        diag.record_other_drop("ghost");
        let groups: HashMap<String, GroupInfo> = HashMap::new();
        let snap = diag.snapshot(&groups, &HashSet::new(), &HashSet::new(), &HashMap::new());
        assert_eq!(snap.groups.len(), 1);
        assert_eq!(snap.groups[0].group_id, "ghost");
        assert_eq!(snap.groups[0].members_v2_size, 0);
        assert_eq!(snap.groups[0].counters.messages_dropped_other, 1);
    }

    /// r3 (#468 A5): `conflict_unauthenticated` is rate-limited to one
    /// increment per group per second — unauthenticated conflict packets
    /// are freely replayable, and the counter must observe pressure, not
    /// the attacker's packet rate. The window is per-GROUP: another
    /// group's conflicts still count.
    #[test]
    fn conflict_unauthenticated_is_rate_limited_per_group() {
        let diag = GroupsDiagnostics::new();
        diag.record_conflict_unauthenticated("grp", 1_000);
        // Same group, inside the 1 s window: suppressed.
        diag.record_conflict_unauthenticated("grp", 1_500);
        diag.record_conflict_unauthenticated("grp", 1_999);
        // Window boundary (1_000 + 1_000): counts again.
        diag.record_conflict_unauthenticated("grp", 2_000);
        // A different group is independently rate-limited.
        diag.record_conflict_unauthenticated("other", 1_500);

        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        groups.insert("grp".into(), group("Grp", "grp"));
        groups.insert("other".into(), group("Other", "other"));
        let snap = diag.snapshot(&groups, &HashSet::new(), &HashSet::new(), &HashMap::new());
        let g = snap.groups.iter().find(|g| g.group_id == "grp").unwrap();
        assert_eq!(
            g.counters.conflict_unauthenticated, 2,
            "only window-crossing attempts may increment"
        );
        let other = snap.groups.iter().find(|g| g.group_id == "other").unwrap();
        assert_eq!(other.counters.conflict_unauthenticated, 1);
    }

    /// r3 (#468 A5): fork-evidence diagnostics fire exactly ONCE per
    /// identity — a second identical conflict must not re-warn or
    /// re-increment `adoption_fork_evidence`, while a DIFFERENT identity
    /// for the same group still fires. `committed_by` is
    /// case-insensitive, mirroring the lineage record's identity check.
    #[test]
    fn fork_evidence_once_fires_only_for_new_identities() {
        let diag = GroupsDiagnostics::new();
        assert!(diag.record_fork_evidence_once("grp", 7, "hash-a", &"AB".repeat(32)));
        // Same identity, differently-cased committer: silent.
        assert!(!diag.record_fork_evidence_once("grp", 7, "hash-a", &"ab".repeat(32)));
        // Same identity again: silent.
        assert!(!diag.record_fork_evidence_once("grp", 7, "hash-a", &"AB".repeat(32)));
        // Different state hash at the same revision: a NEW conflict — fires.
        assert!(diag.record_fork_evidence_once("grp", 7, "hash-b", &"AB".repeat(32)));

        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        groups.insert("grp".into(), group("Grp", "grp"));
        let snap = diag.snapshot(&groups, &HashSet::new(), &HashSet::new(), &HashMap::new());
        let g = snap.groups.iter().find(|g| g.group_id == "grp").unwrap();
        assert_eq!(
            g.counters.adoption_fork_evidence, 2,
            "two distinct identities fired; the replay did not"
        );
    }

    /// r3 (#469 D2 / Codex 8): the snapshot's `members_awaiting_certificate`
    /// gauge counts ACTIVE digest-only seats — a committed
    /// `certificate_digest` without certificate bytes. Inactive seats and
    /// fully-certified seats do not count.
    #[test]
    fn snapshot_counts_active_digest_only_members_as_awaiting_certificate() {
        let mut info = group("Grp", "grp");
        info.add_member(
            "aa".repeat(32),
            crate::groups::GroupRole::Member,
            None,
            None,
        );
        info.add_member(
            "bb".repeat(32),
            crate::groups::GroupRole::Member,
            None,
            None,
        );
        info.add_member(
            "cc".repeat(32),
            crate::groups::GroupRole::Member,
            None,
            None,
        );
        // Digest-only ACTIVE seat — awaiting hydration.
        info.members_v2
            .get_mut(&"aa".repeat(32))
            .unwrap()
            .certificate_digest = Some("00".repeat(32));
        // Fully-certified ACTIVE seat — not awaiting.
        {
            let seat = info.members_v2.get_mut(&"bb".repeat(32)).unwrap();
            seat.certificate_digest = Some("11".repeat(32));
            seat.certificate = Some(certified_stub_certificate());
        }
        // Digest-only but NOT active — not awaiting.
        {
            let seat = info.members_v2.get_mut(&"cc".repeat(32)).unwrap();
            seat.state = crate::groups::GroupMemberState::Removed;
            seat.certificate_digest = Some("22".repeat(32));
        }

        let mut groups: HashMap<String, GroupInfo> = HashMap::new();
        groups.insert("grp".into(), info);
        let diag = GroupsDiagnostics::new();
        let snap = diag.snapshot(&groups, &HashSet::new(), &HashSet::new(), &HashMap::new());
        let g = snap.groups.iter().find(|g| g.group_id == "grp").unwrap();
        assert_eq!(g.counters.members_awaiting_certificate, 1);
    }

    /// Minimal certificate value for the gauge test — the gauge only
    /// inspects `certificate.is_some()`, never verifies the bytes.
    fn certified_stub_certificate() -> crate::identity::AgentCertificate {
        let owner = crate::identity::UserKeypair::generate().expect("user keypair");
        let agent = crate::identity::AgentKeypair::generate().expect("agent keypair");
        crate::identity::AgentCertificate::issue(&owner, &agent).expect("stub cert issue")
    }
}
