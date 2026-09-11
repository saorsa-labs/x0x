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
    /// #477: terminal join-attempt outcomes and refusal-serve bookkeeping.
    pub join_attempts_timed_out: u64,
    pub join_refusal_stale_attempt: u64,
    pub join_refusal_signing_throttled: u64,
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
    /// ADR-0064 slice 1: owner-axis groups whose authenticated fork
    /// evidence durably installed the persistent fork-quarantine marker
    /// (owner-axis only — non-owner-axis groups are out of scope for
    /// this slice and never increment it).
    pub fork_quarantine_set: u64,
    /// ADR-0064 slice 1: membership-gated route refusals (public send,
    /// TreeKEM encrypt/decrypt, secure encrypt/open/reseal) while the
    /// marker is set.
    pub fork_quarantine_refusals: u64,
    /// ADR-0064 slice 2: owner USER-key mandates minted by THIS install
    /// at the pre-mutation point of an invite-derived seat (owner-axis
    /// groups where the local agent holds the owner user key).
    pub owner_mandate_minted: u64,
    /// ADR-0064 slice 2: inbound owner-axis `MemberAdded` events whose
    /// PRESENT mandate verified (verify-if-present; capability recorded).
    pub owner_mandate_valid: u64,
    /// ADR-0064 slice 2: inbound owner-axis `MemberAdded` events whose
    /// present mandate FAILED verification — rejected with state
    /// byte-identical.
    pub owner_mandate_invalid: u64,
    /// ADR-0064 slice 2: owner-axis `MemberAdded` events applied with NO
    /// mandate (pre-mandate authority or keyless tier; warn-accept until
    /// slice-3 enforcement).
    pub owner_mandate_absent: u64,
    /// ADR-0064 slice 3: owner-axis `MemberAdded` events REFUSED because
    /// the event actor is a recorded-capable authority past its grace
    /// window and carried no valid mandate (typed, retryable
    /// `owner_mandate_missing`; state byte-identical).
    pub owner_mandate_missing: u64,
    /// ADR-0064 §1b (slice 3 r2): one-shot `Capable → Refusing`
    /// transitions per (group, authority agent) — counted on the FIRST
    /// refusal of a Refusing episode; the next valid mandate from that
    /// agent restores `Capable` so a later refusal counts again. The
    /// per-agent refusal counts live on the capability map.
    pub mandate_capability_refusing_transitions: u64,
    /// ADR-0064 slice 3 (#472 decision 1): manual fork-quarantine clears
    /// through `POST /groups/:id/quarantine/clear` (owner-key node clear
    /// or `force` + non-empty reason).
    pub fork_quarantine_manual_clears: u64,
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
    /// ADR-0064 §1b: per-authority-agent capability phases observed for
    /// this group (`capable`/`refusing`, derived from the persisted
    /// `first_seen_ms` and the configured grace window). Agents with no
    /// recorded capability are `unknown` and never appear — the absent
    /// map entry IS that state.
    pub mandate_capability: Vec<MandateCapabilityDiagnostic>,
}

/// One ADR-0064 §1b per-agent capability row in
/// `GET /diagnostics/groups`.
#[derive(Debug, Clone, Serialize)]
pub struct MandateCapabilityDiagnostic {
    /// Hex agent id of the authority the state is recorded for.
    pub agent_id: String,
    /// Derived phase: `capable` or `refusing` (never `unknown` — an
    /// unknown agent has no map entry and so no row).
    pub state: &'static str,
    /// Unix ms of the first capability observation (the grace clock
    /// anchor; retained across later valid mandates).
    pub first_seen_ms: u64,
    /// ADR-0064 §1b (slice 3 r2): absent-mandate events from this agent
    /// refused with `owner_mandate_missing` — the per-agent count,
    /// sourced from the persisted capability map.
    pub refusals: u64,
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

/// Sum two counter tables field-by-field (saturating). Module-scoped so
/// the round-2 regression test can drive EVERY field directly — a
/// dropped line fails the test instead of silently under-counting
/// `/diagnostics/groups` fleet aggregates.
fn merge_counters(dst: &mut GroupCounters, src: &GroupCounters) {
    dst.messages_received = dst.messages_received.saturating_add(src.messages_received);
    dst.messages_dropped_decode_failed = dst
        .messages_dropped_decode_failed
        .saturating_add(src.messages_dropped_decode_failed);
    dst.join_attempts_timed_out = dst
        .join_attempts_timed_out
        .saturating_add(src.join_attempts_timed_out);
    dst.join_refusal_stale_attempt = dst
        .join_refusal_stale_attempt
        .saturating_add(src.join_refusal_stale_attempt);
    dst.join_refusal_signing_throttled = dst
        .join_refusal_signing_throttled
        .saturating_add(src.join_refusal_signing_throttled);
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
    dst.fork_quarantine_set = dst
        .fork_quarantine_set
        .saturating_add(src.fork_quarantine_set);
    dst.fork_quarantine_refusals = dst
        .fork_quarantine_refusals
        .saturating_add(src.fork_quarantine_refusals);
    dst.owner_mandate_minted = dst
        .owner_mandate_minted
        .saturating_add(src.owner_mandate_minted);
    dst.owner_mandate_valid = dst
        .owner_mandate_valid
        .saturating_add(src.owner_mandate_valid);
    dst.owner_mandate_invalid = dst
        .owner_mandate_invalid
        .saturating_add(src.owner_mandate_invalid);
    dst.owner_mandate_absent = dst
        .owner_mandate_absent
        .saturating_add(src.owner_mandate_absent);
    dst.causal_queued = dst.causal_queued.saturating_add(src.causal_queued);
    dst.causal_relayed = dst.causal_relayed.saturating_add(src.causal_relayed);
    dst.causal_retried = dst.causal_retried.saturating_add(src.causal_retried);
    dst.causal_deduplicated = dst
        .causal_deduplicated
        .saturating_add(src.causal_deduplicated);
    dst.causal_applied = dst.causal_applied.saturating_add(src.causal_applied);
    dst.owner_mandate_missing = dst
        .owner_mandate_missing
        .saturating_add(src.owner_mandate_missing);
    dst.mandate_capability_refusing_transitions = dst
        .mandate_capability_refusing_transitions
        .saturating_add(src.mandate_capability_refusing_transitions);
    dst.fork_quarantine_manual_clears = dst
        .fork_quarantine_manual_clears
        .saturating_add(src.fork_quarantine_manual_clears);
    dst.membership_events_queued_revision_gap = dst
        .membership_events_queued_revision_gap
        .saturating_add(src.membership_events_queued_revision_gap);
    dst.causal_expired = dst.causal_expired.saturating_add(src.causal_expired);
    dst.causal_invalid = dst.causal_invalid.saturating_add(src.causal_invalid);
    dst.causal_conflicted = dst.causal_conflicted.saturating_add(src.causal_conflicted);
    dst.causal_capacity_rejected = dst
        .causal_capacity_rejected
        .saturating_add(src.causal_capacity_rejected);
    dst.last_message_at_ms = match (dst.last_message_at_ms, src.last_message_at_ms) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (None, Some(b)) => Some(b),
        (a, None) => a,
    };
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

    /// ADR-0064 slice 2: an owner mandate was minted by this install at
    /// the pre-mutation point of an invite-derived seat.
    pub fn record_owner_mandate_minted(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.owner_mandate_minted = c.owner_mandate_minted.saturating_add(1);
        });
    }

    /// ADR-0064 slice 2: an inbound owner-axis `MemberAdded` carried a
    /// mandate that verified (verify-if-present; capability recorded).
    pub fn record_owner_mandate_valid(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.owner_mandate_valid = c.owner_mandate_valid.saturating_add(1);
        });
    }

    /// ADR-0064 slice 2: an inbound owner-axis `MemberAdded` carried a
    /// mandate that FAILED verification — the event was rejected with
    /// state byte-identical.
    pub fn record_owner_mandate_invalid(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.owner_mandate_invalid = c.owner_mandate_invalid.saturating_add(1);
        });
    }

    /// ADR-0064 slice 2: an owner-axis `MemberAdded` applied with NO
    /// mandate (warn-accept until slice-3 enforcement).
    pub fn record_owner_mandate_absent(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.owner_mandate_absent = c.owner_mandate_absent.saturating_add(1);
        });
    }

    /// ADR-0064 slice 3: an owner-axis `MemberAdded` was refused with the
    /// typed, retryable `owner_mandate_missing` — the event actor is a
    /// recorded-capable authority past its grace window and carried no
    /// mandate. The per-agent breakdown lives on the persisted capability
    /// map (`MandateCapabilityState::refusals`).
    pub fn record_owner_mandate_missing(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.owner_mandate_missing = c.owner_mandate_missing.saturating_add(1);
        });
    }

    /// ADR-0064 §1b (slice 3 r2): a one-shot `Capable → Refusing`
    /// transition — counted on the FIRST refusal of a Refusing episode;
    /// the next valid mandate from that agent clears the episode (the
    /// `Refusing → Capable` edge) so a later refusal counts again.
    pub fn record_mandate_capability_refusing_transition(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.mandate_capability_refusing_transitions =
                c.mandate_capability_refusing_transitions.saturating_add(1);
        });
    }

    /// ADR-0064 slice 3 (#472 decision 1): the local fork-quarantine
    /// marker was cleared through the manual endpoint.
    pub fn record_fork_quarantine_manual_clear(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.fork_quarantine_manual_clears = c.fork_quarantine_manual_clears.saturating_add(1);
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

    /// ADR-0064 slice 1: the persistent fork-quarantine marker was
    /// durably installed for this group (owner-axis groups only — see
    /// `GroupCounters::fork_quarantine_set`).
    pub fn record_fork_quarantine_set(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.fork_quarantine_set = c.fork_quarantine_set.saturating_add(1);
        });
    }

    /// ADR-0064 slice 1: a membership-gated route refused the group
    /// because the fork-quarantine marker is set (typed 409
    /// `fork_quarantined`).
    pub fn record_fork_quarantine_refusal(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.fork_quarantine_refusals = c.fork_quarantine_refusals.saturating_add(1);
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
    /// #477: record a join attempt that timed out without any authority
    /// answer (the poll deadline owner's terminal path).
    pub fn record_join_attempt_timed_out(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.join_attempts_timed_out = c.join_attempts_timed_out.saturating_add(1);
        });
    }

    /// #477: record a refusal serve skipped because the fetch's attempt id
    /// does not match the staged refusal (stale attempt).
    pub fn record_join_refusal_stale_attempt(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.join_refusal_stale_attempt = c.join_refusal_stale_attempt.saturating_add(1);
        });
    }

    /// #477: record a refusal serve skipped because the signing rate
    /// limiter had no budget.
    pub fn record_join_refusal_signing_throttled(&self, group_id: &str) {
        self.with_counters(group_id, |c| {
            c.join_refusal_signing_throttled = c.join_refusal_signing_throttled.saturating_add(1);
        });
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
    /// the call stack, so we keep this function pure-sync). The
    /// ADR-0064 §1b grace window (days) derives each recorded
    /// capability's `capable`/`refusing` phase at snapshot time.
    #[must_use]
    pub fn snapshot(
        &self,
        groups: &HashMap<String, GroupInfo>,
        metadata_subscribed: &HashSet<String>,
        public_subscribed: &HashSet<String>,
        causal_gauges: &HashMap<String, CausalGauges>,
        mandate_grace_days: u64,
    ) -> GroupsDiagnosticsSnapshot {
        let counters_guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now_ms = super::now_millis();

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
                    mandate_capability: info
                        .mandate_capability
                        .iter()
                        .map(|(agent_id, capability)| MandateCapabilityDiagnostic {
                            agent_id: agent_id.clone(),
                            state: capability.phase_label(mandate_grace_days, now_ms),
                            first_seen_ms: capability.first_seen_ms,
                            refusals: capability.refusals,
                        })
                        .collect(),
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
                    // Counters-only rows have no GroupInfo to derive
                    // capability phases from (the map lives on the record).
                    mandate_capability: Vec::new(),
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

        let snap = diag.snapshot(&groups, &meta, &pub_set, &HashMap::new(), 60);
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
        let snap = diag.snapshot(
            &groups,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            60,
        );

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
        let snap = diag.snapshot(
            &groups,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            60,
        );
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
        let snap = diag.snapshot(
            &groups,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            60,
        );
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
        let snap = diag.snapshot(
            &groups,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            60,
        );
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
        let snap = diag.snapshot(
            &groups,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            60,
        );
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
        let snap = diag.snapshot(
            &groups,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            60,
        );
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
    /// ADR-0064 r2 / review item 1: the #635 merge hunk dropped the
    /// `causal_applied` line, which no existing test caught. This test
    /// drives EVERY merged field with distinct non-zero values on both
    /// sides and asserts each sum, so any future dropped (or wrongly
    /// doubled) merge line fails here instead of silently under-counting
    /// `/diagnostics/groups` fleet aggregates.
    #[test]
    fn merge_counters_sums_every_field() {
        let counters_with = |base: u64| GroupCounters {
            messages_received: base + 1,
            messages_dropped_decode_failed: base + 2,
            messages_dropped_author_banned: base + 3,
            messages_dropped_write_policy_violation: base + 4,
            sends_rejected_write_policy: base + 5,
            public_message_gossip_raced_unicast: base + 6,
            messages_dropped_signature_failed: base + 7,
            messages_dropped_other: base + 8,
            last_message_at_ms: Some(base + 9),
            member_joined_events_applied: base + 10,
            member_joined_events_rejected_non_member_role: base + 11,
            member_joined_events_rejected_invite_secret_unknown: base + 12,
            invites_refused_reasons: std::collections::BTreeMap::from([(
                "reason-a".to_string(),
                base + 13,
            )]),
            join_attempts_timed_out: base + 14,
            join_refusal_stale_attempt: base + 15,
            join_refusal_signing_throttled: base + 16,
            adoption_fork_evidence: base + 17,
            conflict_unauthenticated: base + 18,
            // Snapshot-time gauge, NOT a merged counter: set non-zero to
            // pin that merge leaves it alone (snapshot recomputes it).
            members_awaiting_certificate: base + 19,
            member_joined_events_rejected_owner_cert_pending: base + 20,
            member_joined_events_rejected_treekem_unavailable: base + 21,
            member_added_events_adopted: base + 22,
            member_added_events_rejected_state_chain_gap: base + 23,
            causal_relayed: base + 24,
            causal_retried: base + 25,
            causal_queued: base + 26,
            causal_deduplicated: base + 27,
            causal_applied: base + 28,
            causal_expired: base + 29,
            causal_invalid: base + 30,
            causal_conflicted: base + 31,
            causal_capacity_rejected: base + 32,
            membership_events_queued_revision_gap: base + 33,
            fork_quarantine_set: base + 34,
            fork_quarantine_refusals: base + 35,
            owner_mandate_minted: base + 36,
            owner_mandate_valid: base + 37,
            owner_mandate_invalid: base + 38,
            owner_mandate_absent: base + 39,
            owner_mandate_missing: base + 40,
            mandate_capability_refusing_transitions: base + 41,
            fork_quarantine_manual_clears: base + 42,
        };
        let src = counters_with(1_000);
        let dst = counters_with(7);
        let gauge_before = dst.members_awaiting_certificate;
        let mut merged = dst.clone();
        merge_counters(&mut merged, &src);
        // Every merged counter must equal the exact per-field sum — a
        // dropped merge line leaves dst's value; a doubled line over-sums.
        assert_eq!(
            merged.messages_received,
            dst.messages_received + src.messages_received
        );
        assert_eq!(
            merged.messages_dropped_decode_failed,
            dst.messages_dropped_decode_failed + src.messages_dropped_decode_failed
        );
        assert_eq!(
            merged.messages_dropped_author_banned,
            dst.messages_dropped_author_banned + src.messages_dropped_author_banned
        );
        assert_eq!(
            merged.messages_dropped_write_policy_violation,
            dst.messages_dropped_write_policy_violation
                + src.messages_dropped_write_policy_violation
        );
        assert_eq!(
            merged.sends_rejected_write_policy,
            dst.sends_rejected_write_policy + src.sends_rejected_write_policy
        );
        assert_eq!(
            merged.public_message_gossip_raced_unicast,
            dst.public_message_gossip_raced_unicast + src.public_message_gossip_raced_unicast
        );
        assert_eq!(
            merged.messages_dropped_signature_failed,
            dst.messages_dropped_signature_failed + src.messages_dropped_signature_failed
        );
        assert_eq!(
            merged.messages_dropped_other,
            dst.messages_dropped_other + src.messages_dropped_other
        );
        assert_eq!(
            merged.last_message_at_ms,
            dst.last_message_at_ms.max(src.last_message_at_ms)
        );
        assert_eq!(
            merged.member_joined_events_applied,
            dst.member_joined_events_applied + src.member_joined_events_applied
        );
        assert_eq!(
            merged.member_joined_events_rejected_non_member_role,
            dst.member_joined_events_rejected_non_member_role
                + src.member_joined_events_rejected_non_member_role
        );
        assert_eq!(
            merged.member_joined_events_rejected_invite_secret_unknown,
            dst.member_joined_events_rejected_invite_secret_unknown
                + src.member_joined_events_rejected_invite_secret_unknown
        );
        assert_eq!(
            merged.invites_refused_reasons.get("reason-a"),
            Some(
                &(dst.invites_refused_reasons.get("reason-a").unwrap()
                    + src.invites_refused_reasons.get("reason-a").unwrap())
            )
        );
        assert_eq!(merged.invites_refused_reasons.len(), 1);
        assert_eq!(
            merged.join_attempts_timed_out,
            dst.join_attempts_timed_out + src.join_attempts_timed_out
        );
        assert_eq!(
            merged.join_refusal_stale_attempt,
            dst.join_refusal_stale_attempt + src.join_refusal_stale_attempt
        );
        assert_eq!(
            merged.join_refusal_signing_throttled,
            dst.join_refusal_signing_throttled + src.join_refusal_signing_throttled
        );
        assert_eq!(
            merged.adoption_fork_evidence,
            dst.adoption_fork_evidence + src.adoption_fork_evidence
        );
        assert_eq!(
            merged.conflict_unauthenticated,
            dst.conflict_unauthenticated + src.conflict_unauthenticated
        );
        assert_eq!(
            merged.member_joined_events_rejected_owner_cert_pending,
            dst.member_joined_events_rejected_owner_cert_pending
                + src.member_joined_events_rejected_owner_cert_pending
        );
        assert_eq!(
            merged.member_joined_events_rejected_treekem_unavailable,
            dst.member_joined_events_rejected_treekem_unavailable
                + src.member_joined_events_rejected_treekem_unavailable
        );
        assert_eq!(
            merged.member_added_events_adopted,
            dst.member_added_events_adopted + src.member_added_events_adopted
        );
        assert_eq!(
            merged.member_added_events_rejected_state_chain_gap,
            dst.member_added_events_rejected_state_chain_gap
                + src.member_added_events_rejected_state_chain_gap
        );
        assert_eq!(
            merged.causal_relayed,
            dst.causal_relayed + src.causal_relayed
        );
        assert_eq!(
            merged.causal_retried,
            dst.causal_retried + src.causal_retried
        );
        assert_eq!(merged.causal_queued, dst.causal_queued + src.causal_queued);
        assert_eq!(
            merged.causal_deduplicated,
            dst.causal_deduplicated + src.causal_deduplicated
        );
        assert_eq!(
            merged.causal_applied,
            dst.causal_applied + src.causal_applied
        );
        assert_eq!(
            merged.causal_expired,
            dst.causal_expired + src.causal_expired
        );
        assert_eq!(
            merged.causal_invalid,
            dst.causal_invalid + src.causal_invalid
        );
        assert_eq!(
            merged.causal_conflicted,
            dst.causal_conflicted + src.causal_conflicted
        );
        assert_eq!(
            merged.causal_capacity_rejected,
            dst.causal_capacity_rejected + src.causal_capacity_rejected
        );
        assert_eq!(
            merged.membership_events_queued_revision_gap,
            dst.membership_events_queued_revision_gap + src.membership_events_queued_revision_gap
        );
        assert_eq!(
            merged.fork_quarantine_set,
            dst.fork_quarantine_set + src.fork_quarantine_set
        );
        assert_eq!(
            merged.fork_quarantine_refusals,
            dst.fork_quarantine_refusals + src.fork_quarantine_refusals
        );
        // The gauge is recomputed at snapshot time, never merged.
        assert_eq!(
            merged.owner_mandate_minted,
            dst.owner_mandate_minted + src.owner_mandate_minted
        );
        assert_eq!(
            merged.owner_mandate_valid,
            dst.owner_mandate_valid + src.owner_mandate_valid
        );
        assert_eq!(
            merged.owner_mandate_invalid,
            dst.owner_mandate_invalid + src.owner_mandate_invalid
        );
        assert_eq!(
            merged.owner_mandate_absent,
            dst.owner_mandate_absent + src.owner_mandate_absent
        );
        assert_eq!(
            merged.owner_mandate_missing,
            dst.owner_mandate_missing + src.owner_mandate_missing
        );
        assert_eq!(
            merged.mandate_capability_refusing_transitions,
            dst.mandate_capability_refusing_transitions
                + src.mandate_capability_refusing_transitions
        );
        assert_eq!(
            merged.fork_quarantine_manual_clears,
            dst.fork_quarantine_manual_clears + src.fork_quarantine_manual_clears
        );
        assert_eq!(merged.members_awaiting_certificate, gauge_before);
    }
}
