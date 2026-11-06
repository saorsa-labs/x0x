//! #908: the REQUESTER's durable predecessor-offer outbox.
//!
//! When a requester publishes `JoinRequestCreated`, the exact signed
//! predecessor envelope must reach the group's authority (the creator) so
//! the authority can satisfy the ADR 0028 B8 approval precondition. The
//! offer used to be a one-shot spawned DM: if the send exhausted its
//! retries the task only WARNed, and nothing survived a restart.
//!
//! This module reuses the #903 `predecessor_relay_outbox` pattern on the
//! requester side (issue #908):
//!
//! - an obligation is keyed by `(group, request_id)` and persisted to
//!   `<data_dir>/requester_offer_outbox.json` (durable, 0600, atomic)
//!   before the join-request response returns;
//! - a bounded-backoff worker retries the offer over the gossip-only
//!   delivery config (`predecessor_relay_delivery_config`, per #913: no
//!   raw fallback), so a full typed channel is a retry, never a silent
//!   loss. The backoff caps the retry INTERVAL (ADR 0028 offsets, then
//!   the 240 s tail FOREVER — #942 B1), never the attempt count: the
//!   obligation lives until the authority ACKs, the join resolves, or
//!   the store caps evict it;
//! - the obligation is cleared when the authority ACKs (send `Ok`) or
//!   when the join resolves — approved, denied, expired, cancelled, the
//!   request vanishing, or the group being withdrawn;
//! - the store is capped with the same ADR 0028 bounds as the relay
//!   outbox (per-group and per-daemon envelope/byte caps, oldest evicted
//!   first) and survives restart (loaded at boot).
//!
//! A malformed store never blocks startup: the file is left untouched,
//! the error is surfaced, and the outbox starts empty (fail-visible; the
//! pending join request itself remains durably recorded in the group
//! state, and the authority can still observe the `JoinRequestCreated`
//! metadata event on the group topic).
//!
//! #1365 (D18): the commit, caps, retry and boot-load logic is the
//! generic [`Outbox`]. This module keeps the record, its sidecar codec
//! (the v1 bytes are unchanged), the liveness check and the send.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    now_millis_u64, parse_agent_id_hex, predecessor_relay_delivery_config,
    predecessor_relay_legacy_delivery_config, predecessor_relay_wire_version,
    CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP, CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP,
    CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP, CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP,
    CAUSAL_RELAY_RETRY_SECS, GROUP_PREDECESSOR_RELAY_DM_PREFIX,
};
use crate::server::state::AppState;
use crate::storage::outbox::{Outbox, OutboxCaps, OutboxMap, OutboxRecord, Settled};

/// Sidecar format version.
const REQUESTER_OFFER_OUTBOX_VERSION: u32 = 1;

/// The ADR 0028 caps (the relay outbox's bounds).
const REQUESTER_OFFER_CAPS: OutboxCaps = OutboxCaps {
    per_partition: CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP,
    per_partition_bytes: CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP,
    total: CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP,
    total_bytes: CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP,
};

/// A durable requester→authority predecessor-offer obligation (#908).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::server) struct RequesterOfferObligation {
    /// The group id the join request belongs to (stable id).
    pub(in crate::server) group_id: String,
    /// The join request id this offer carries.
    pub(in crate::server) request_id: String,
    /// The requester agent id (hex) — this daemon's own agent.
    pub(in crate::server) requester_agent_id: String,
    /// The authority the envelope is offered to (hex; the group creator).
    pub(in crate::server) authority_agent_id: String,
    /// The exact requester-signed V2 wire envelope bytes.
    pub(in crate::server) envelope_bytes: Vec<u8>,
    /// blake3 digest of the envelope bytes (identity within the group).
    pub(in crate::server) digest: [u8; 32],
    /// Serialized byte size of `envelope_bytes` (cap accounting).
    pub(in crate::server) byte_size: usize,
    /// Unix-epoch millis when the obligation was first created.
    pub(in crate::server) first_seen_ms: u64,
    /// Unix-epoch millis for the next scheduled offer attempt.
    pub(in crate::server) next_retry_at_ms: u64,
    /// Offer attempts completed so far.
    pub(in crate::server) retry_count: u32,
}

/// Sidecar shape: version + obligations grouped by group id.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequesterOfferOutboxFile {
    version: u32,
    #[serde(default)]
    by_group: HashMap<String, Vec<RequesterOfferObligation>>,
}

impl OutboxRecord for RequesterOfferObligation {
    const LABEL: &'static str = "requester offer outbox";

    fn partition(&self) -> &str {
        &self.group_id
    }

    fn id(&self) -> &str {
        &self.request_id
    }

    fn first_seen_ms(&self) -> u64 {
        self.first_seen_ms
    }

    fn byte_size(&self) -> usize {
        self.byte_size
    }

    fn next_retry_at_ms(&self) -> u64 {
        self.next_retry_at_ms
    }

    fn retry_count(&self) -> u32 {
        self.retry_count
    }

    fn set_schedule(&mut self, retry_count: u32, next_retry_at_ms: u64) {
        self.retry_count = retry_count;
        self.next_retry_at_ms = next_retry_at_ms;
    }

    /// #942 M3: `byte_size` must match the envelope it describes and the
    /// digest must be its blake3.
    fn check(&self) -> Result<(), String> {
        if self.byte_size != self.envelope_bytes.len() {
            return Err(format!("byte_size mismatch on {}", self.request_id));
        }
        if blake3::hash(&self.envelope_bytes).as_bytes() != &self.digest {
            return Err(format!("digest mismatch on {}", self.request_id));
        }
        Ok(())
    }

    fn encode(map: &OutboxMap<Self>) -> Result<Vec<u8>, String> {
        let file = RequesterOfferOutboxFile {
            version: REQUESTER_OFFER_OUTBOX_VERSION,
            by_group: map.clone(),
        };
        serde_json::to_vec(&file)
            .map_err(|e| format!("failed to encode requester offer outbox: {e}"))
    }

    fn decode(bytes: &[u8], path: &Path) -> Result<OutboxMap<Self>, String> {
        let file: RequesterOfferOutboxFile = serde_json::from_slice(bytes)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
        if file.version != REQUESTER_OFFER_OUTBOX_VERSION {
            return Err(format!(
                "{}: unsupported requester offer outbox version {} (expected {REQUESTER_OFFER_OUTBOX_VERSION})",
                path.display(),
                file.version
            ));
        }
        Ok(file.by_group)
    }
}

/// The requester offer outbox over the daemon's state cells.
fn outbox(state: &AppState) -> Outbox<'_, RequesterOfferObligation> {
    Outbox::new(
        &state.requester_offer_outbox,
        &state.requester_offer_outbox_path,
        &state.requester_offer_outbox_persistence_lock,
        REQUESTER_OFFER_CAPS,
    )
}

/// Insert (or replace, on a repeated `(group, request_id)`) one
/// obligation, enforcing the ADR 0028 caps, and persist durably. The
/// in-memory map changes only after the durable write succeeds; a
/// non-durable outcome keeps the last durable set in force — except a
/// failure AFTER the rename (issue #1101), where the disk already holds
/// the new set, so memory commits to match it while the error still
/// reports that durability is unconfirmed.
pub(in crate::server) async fn insert_requester_offer_obligation(
    state: &AppState,
    obligation: RequesterOfferObligation,
) -> Result<(), String> {
    match outbox(state).insert(obligation).await {
        Ok(()) => Ok(()),
        Err(e) if e.crossed_rename() => Err(format!(
            "applied, but durability is not confirmed (directory fsync failed): {e}; \
             the change is in effect"
        )),
        Err(e) => Err(format!("failed to write requester offer outbox: {e}")),
    }
}

/// Load the outbox at boot. Missing ⇒ empty. Malformed, wrong version, or
/// over the daemon caps ⇒ empty + an error, and the file is moved aside
/// (#942 M2) so the operator keeps the evidence and the next insert
/// writes a fresh sidecar.
pub(in crate::server) async fn load_requester_offer_outbox(state: &AppState) -> Result<(), String> {
    outbox(state).load(now_millis_u64()).await
}

/// Is the obligation's join still live — pending, in a live group? When
/// this is false the offer can never matter again (an authority may only
/// act on a pending request), so the worker drops it.
async fn offer_still_live(state: &AppState, obligation: &RequesterOfferObligation) -> bool {
    let groups = state.named_groups.read().await;
    let Some((_, info)) = crate::server::resolve_group_entry_locked(&groups, &obligation.group_id)
    else {
        return false;
    };
    if info.withdrawn {
        return false;
    }
    info.join_requests
        .get(&obligation.request_id)
        .is_some_and(|r| r.is_pending() && r.requester_agent_id == obligation.requester_agent_id)
}

/// One worker pass (#908): drop resolved obligations, deliver every due
/// one, then persist exactly what happened — persist-before-count with a
/// full snapshot rollback on a failed write (the relay outbox's
/// discipline).
pub(in crate::server) async fn requester_offer_step(state: &std::sync::Arc<AppState>) {
    let now_ms = now_millis_u64();
    // #942 r4/r5 (B8): `due` is in send order — FIRST ATTEMPTS ahead of
    // retries, oldest-due within each class — so a brand-new offer is
    // attempted in the FIRST pass even behind a full retry backlog.
    let due = outbox(state).due(now_ms).await;
    if due.is_empty() {
        return;
    }
    let mut resolved: Vec<RequesterOfferObligation> = Vec::new();
    let mut to_send: Vec<RequesterOfferObligation> = Vec::new();
    for obligation in due {
        if offer_still_live(state, &obligation).await {
            to_send.push(obligation);
        } else {
            resolved.push(obligation);
        }
    }
    // #942 r4 (bounded pass): a per-pass SEND budget — a hundred slow
    // strict sends can no longer starve a brand-new obligation behind
    // one 500 ms-tick pass. Unserved obligations stay due for the next
    // tick.
    const REQUESTER_OFFER_PASS_BUDGET: usize = 16;
    let mut attempts: Vec<(RequesterOfferObligation, bool)> = Vec::new();
    for obligation in to_send.into_iter().take(REQUESTER_OFFER_PASS_BUDGET) {
        let Ok(authority) = parse_agent_id_hex(&obligation.authority_agent_id) else {
            attempts.push((obligation, false));
            continue;
        };
        let mut dm_payload = Vec::with_capacity(
            GROUP_PREDECESSOR_RELAY_DM_PREFIX.len() + obligation.envelope_bytes.len(),
        );
        dm_payload.extend_from_slice(GROUP_PREDECESSOR_RELAY_DM_PREFIX);
        dm_payload.extend_from_slice(&obligation.envelope_bytes);
        // #942 r3 (B4): dual-wire delivery, the bootstrap-outbox pattern.
        // A v2-capable authority gets the STRICT config (send Ok = the
        // handler's durable disposition, logical_request_id makes retries
        // replays); a legacy or history-less authority gets the v1 gossip
        // config (transport receipt, same payload, same prefix) so the
        // offer still reaches it — the pre-durable-route behavior.
        let delivered = if predecessor_relay_wire_version(state, &authority).await {
            state
                .agent
                .send_direct_with_config(
                    &authority,
                    dm_payload,
                    predecessor_relay_delivery_config(&obligation.digest, &authority),
                )
                .await
                .is_ok()
        } else {
            state
                .agent
                .send_direct_with_config(
                    &authority,
                    dm_payload,
                    predecessor_relay_legacy_delivery_config(),
                )
                .await
                .is_ok()
        };
        attempts.push((obligation, delivered));
    }
    // Settle under the persistence lock: mutate → durable write → count.
    // #942 B1: a FAILED send never leaves the store — the bounded
    // backoff caps the retry INTERVAL (the 240 s tail repeats), not the
    // attempt count.
    match outbox(state)
        .settle(now_ms, &resolved, &attempts, CAUSAL_RELAY_RETRY_SECS)
        .await
    {
        Settled::Committed { delivered, dropped } => {
            // Persist-before-count: diagnostics advance only on a durable
            // store.
            for group_id in &delivered {
                state
                    .groups_diagnostics
                    .record_requester_offer_delivered(group_id);
            }
            for group_id in &dropped {
                state
                    .groups_diagnostics
                    .record_requester_offer_resolved_drop(group_id);
            }
        }
        Settled::Unconfirmed(e) => {
            // #1101: the rename already happened — disk and memory hold
            // the new set. Diagnostics stay uncounted: they advance only
            // on a confirmed durable write.
            tracing::error!(
                error = %e,
                "#908: requester offer outbox applied, but durability is not confirmed \
                 (directory fsync failed); the change is in effect — committing the disk \
                 state to memory"
            );
        }
        Settled::RolledBack(e) => {
            tracing::error!(
                error = %e,
                "#908: failed to persist requester offer outbox; rolling back this pass"
            );
        }
    }
}

/// Test-only view of the live store.
#[cfg(test)]
pub(in crate::server) async fn requester_offer_snapshot(
    state: &AppState,
) -> Vec<RequesterOfferObligation> {
    outbox(state).snapshot().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::outbox::enforce_caps;

    fn obligation(group: &str, request: &str, first_seen_ms: u64) -> RequesterOfferObligation {
        RequesterOfferObligation {
            group_id: group.to_string(),
            request_id: request.to_string(),
            requester_agent_id: "aa".repeat(32),
            authority_agent_id: "bb".repeat(32),
            envelope_bytes: vec![1, 2, 3],
            digest: [7; 32],
            byte_size: 3,
            first_seen_ms,
            next_retry_at_ms: 0,
            retry_count: 0,
        }
    }

    #[test]
    fn caps_evict_oldest_first_per_group() {
        let mut by_group = HashMap::new();
        by_group.insert(
            "g".to_string(),
            (0..CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP + 3)
                .map(|i| obligation("g", &format!("r{i}"), i as u64))
                .collect(),
        );
        enforce_caps(&mut by_group, &REQUESTER_OFFER_CAPS);
        let list = &by_group["g"];
        assert_eq!(list.len(), CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP);
        // The OLDEST (smallest first_seen_ms) were evicted.
        assert_eq!(list.first().expect("non-empty").first_seen_ms, 3);
        assert_eq!(
            list.last().expect("non-empty").first_seen_ms,
            CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP as u64 + 2
        );
    }

    #[test]
    fn caps_evict_oldest_daemon_wide_across_groups() {
        // Per-group pressure cannot reach the daemon cap (each group is
        // capped first), so drive it with COUNT across many groups: one
        // obligation per group, more groups than the daemon cap.
        let mut by_group = HashMap::new();
        for g in 0..CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP + 8 {
            by_group.insert(
                format!("g{g}"),
                vec![obligation(&format!("g{g}"), "r", g as u64)],
            );
        }
        enforce_caps(&mut by_group, &REQUESTER_OFFER_CAPS);
        let count: usize = by_group.values().map(|l| l.len()).sum();
        assert_eq!(count, CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP);
        // The OLDEST groups' obligations were evicted: group "g0" (first
        // seen earliest) is gone, the newest survives.
        assert!(!by_group.contains_key("g0"));
        assert!(by_group.contains_key(&format!("g{}", CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP + 7)));
    }
}
