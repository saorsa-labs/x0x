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
//!   raw fallback, and a send only counts when the recipient application
//!   ACKs), so a full typed channel is a retry, never a silent loss;
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

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    now_millis_u64, parse_agent_id_hex, predecessor_relay_delivery_config,
    CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP, CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP,
    CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP, CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP,
    CAUSAL_RELAY_RETRY_SECS, GROUP_PREDECESSOR_RELAY_DM_PREFIX,
};
use crate::server::state::AppState;

/// Sidecar format version.
const REQUESTER_OFFER_OUTBOX_VERSION: u32 = 1;

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

/// Insert (or replace, on a repeated `(group, request_id)`) one
/// obligation, enforcing the ADR 0028 caps, and persist durably. The
/// in-memory map changes only after the durable write succeeds; a
/// non-durable outcome keeps the last durable set in force.
pub(in crate::server) async fn insert_requester_offer_obligation(
    state: &AppState,
    obligation: RequesterOfferObligation,
) -> Result<(), String> {
    let _guard = state.requester_offer_outbox_persistence_lock.lock().await;
    let snapshot = state.requester_offer_outbox.read().await.clone();
    let mut next = snapshot.clone();
    next.entry(obligation.group_id.clone())
        .or_default()
        .retain(|o| o.request_id != obligation.request_id);
    next.get_mut(&obligation.group_id)
        .unwrap_or_else(|| unreachable!("entry just ensured"))
        .push(obligation);
    enforce_caps(&mut next);
    save_requester_offer_outbox(state, &next).await?;
    *state.requester_offer_outbox.write().await = next;
    Ok(())
}

/// Enforce the per-group and per-daemon envelope/byte caps, evicting the
/// OLDEST obligations first (the relay outbox's policy). Pure, so the
/// eviction order is directly testable.
fn enforce_caps(by_group: &mut HashMap<String, Vec<RequesterOfferObligation>>) {
    for list in by_group.values_mut() {
        list.sort_by_key(|o| o.first_seen_ms);
        while list.len() > CAUSAL_RELAY_OUTBOX_PER_GROUP_CAP
            || list.iter().map(|o| o.byte_size).sum::<usize>()
                > CAUSAL_RELAY_OUTBOX_PER_GROUP_BYTE_CAP
        {
            list.remove(0);
            if list.is_empty() {
                break;
            }
        }
    }
    loop {
        let count: usize = by_group.values().map(|l| l.len()).sum();
        let bytes: usize = by_group
            .values()
            .flat_map(|l| l.iter().map(|o| o.byte_size))
            .sum();
        if count <= CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP
            && bytes <= CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP
        {
            break;
        }
        // Evict the single oldest obligation daemon-wide (a linear scan;
        // the store is capped at ~1024 entries).
        let mut oldest: Option<(String, usize)> = None;
        for (group, list) in by_group.iter() {
            for (idx, obligation) in list.iter().enumerate() {
                let better = match &oldest {
                    None => true,
                    Some((og, oidx)) => {
                        obligation.first_seen_ms < by_group[og][*oidx].first_seen_ms
                    }
                };
                if better {
                    oldest = Some((group.clone(), idx));
                }
            }
        }
        let Some((group, idx)) = oldest else { break };
        if let Some(list) = by_group.get_mut(&group) {
            if idx < list.len() {
                list.remove(idx);
            }
        }
    }
    by_group.retain(|_, list| !list.is_empty());
}

/// Durable sidecar write (temp, fsync, 0600, rename, dir fsync — the
/// same helper the owner key and the grant store use).
async fn save_requester_offer_outbox(
    state: &AppState,
    by_group: &HashMap<String, Vec<RequesterOfferObligation>>,
) -> Result<(), String> {
    let file = RequesterOfferOutboxFile {
        version: REQUESTER_OFFER_OUTBOX_VERSION,
        by_group: by_group.clone(),
    };
    let bytes = serde_json::to_vec(&file)
        .map_err(|e| format!("failed to encode requester offer outbox: {e}"))?;
    crate::storage::write_private_bytes_durable(&state.requester_offer_outbox_path, bytes)
        .await
        .map_err(|e| format!("failed to write requester offer outbox: {e}"))
}

/// Load the outbox at boot. Missing ⇒ empty. Malformed, wrong version, or
/// over the daemon caps ⇒ empty + an error log (fail-visible, never
/// blocking startup; the file is left untouched for the operator).
pub(in crate::server) async fn load_requester_offer_outbox(state: &AppState) -> Result<(), String> {
    let path: &Path = &state.requester_offer_outbox_path;
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("failed to read {}: {e}", path.display())),
    };
    let file: RequesterOfferOutboxFile = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    if file.version != REQUESTER_OFFER_OUTBOX_VERSION {
        return Err(format!(
            "{}: unsupported requester offer outbox version {} (expected {REQUESTER_OFFER_OUTBOX_VERSION})",
            path.display(),
            file.version
        ));
    }
    let count: usize = file.by_group.values().map(|l| l.len()).sum();
    let total_bytes: usize = file
        .by_group
        .values()
        .flat_map(|l| l.iter().map(|o| o.byte_size))
        .sum();
    if count > CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP
        || total_bytes > CAUSAL_RELAY_OUTBOX_PER_DAEMON_BYTE_CAP
    {
        return Err(format!(
            "{}: requester offer outbox exceeds daemon caps ({count} envelopes, {total_bytes} bytes)",
            path.display()
        ));
    }
    *state.requester_offer_outbox.write().await = file.by_group;
    Ok(())
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
    let due: Vec<RequesterOfferObligation> = {
        let outbox = state.requester_offer_outbox.read().await;
        outbox
            .values()
            .flatten()
            .filter(|o| o.next_retry_at_ms <= now_ms)
            .cloned()
            .collect()
    };
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
    // (group_id, delivered) per send attempt.
    let mut attempts: Vec<(RequesterOfferObligation, bool)> = Vec::new();
    for obligation in to_send {
        let Ok(authority) = parse_agent_id_hex(&obligation.authority_agent_id) else {
            attempts.push((obligation, false));
            continue;
        };
        let mut dm_payload = Vec::with_capacity(
            GROUP_PREDECESSOR_RELAY_DM_PREFIX.len() + obligation.envelope_bytes.len(),
        );
        dm_payload.extend_from_slice(GROUP_PREDECESSOR_RELAY_DM_PREFIX);
        dm_payload.extend_from_slice(&obligation.envelope_bytes);
        // #913: gossip-only delivery — `Ok` is the recipient APPLICATION
        // ACK of the typed predecessor route, not a transport receipt, so
        // it genuinely discharges the obligation.
        let delivered = state
            .agent
            .send_direct_with_config(&authority, dm_payload, predecessor_relay_delivery_config())
            .await
            .is_ok();
        attempts.push((obligation, delivered));
    }
    // Settle under the persistence lock: mutate → durable write → count.
    let _guard = state.requester_offer_outbox_persistence_lock.lock().await;
    let snapshot = state.requester_offer_outbox.read().await.clone();
    let mut next = snapshot.clone();
    let mut delivered_groups: Vec<String> = Vec::new();
    let mut dropped_resolved: Vec<String> = Vec::new();
    let mut exhausted_groups: Vec<String> = Vec::new();
    {
        for obligation in &resolved {
            if remove_obligation(&mut next, obligation) {
                dropped_resolved.push(obligation.group_id.clone());
            }
        }
        for (obligation, delivered) in &attempts {
            let Some(list) = next.get_mut(&obligation.group_id) else {
                continue;
            };
            let Some(live) = list
                .iter_mut()
                .find(|o| o.request_id == obligation.request_id)
            else {
                continue;
            };
            if *delivered {
                delivered_groups.push(obligation.group_id.clone());
                live.retry_count = live.retry_count.saturating_add(1);
            } else {
                live.retry_count = live.retry_count.saturating_add(1);
                if (live.retry_count as usize) < CAUSAL_RELAY_RETRY_SECS.len() {
                    let delay_secs = CAUSAL_RELAY_RETRY_SECS[(live.retry_count as usize)
                        .saturating_sub(1)
                        .min(CAUSAL_RELAY_RETRY_SECS.len() - 1)];
                    live.next_retry_at_ms = now_ms.saturating_add(delay_secs * 1000);
                    continue;
                }
                exhausted_groups.push(obligation.group_id.clone());
            }
        }
        // Delivered and retry-exhausted obligations leave the store.
        for (obligation, delivered) in &attempts {
            if !*delivered {
                continue;
            }
            if let Some(list) = next.get_mut(&obligation.group_id) {
                list.retain(|o| o.request_id != obligation.request_id);
            }
        }
        for list in next.values_mut() {
            list.retain(|o| (o.retry_count as usize) < CAUSAL_RELAY_RETRY_SECS.len());
        }
        next.retain(|_, list| !list.is_empty());
    }
    if let Err(error) = save_requester_offer_outbox(state, &next).await {
        tracing::error!(
            %error,
            "#908: failed to persist requester offer outbox; rolling back this pass"
        );
        *state.requester_offer_outbox.write().await = snapshot;
        return;
    }
    *state.requester_offer_outbox.write().await = next;
    // Persist-before-count: diagnostics advance only on a durable store.
    for group_id in &delivered_groups {
        state
            .groups_diagnostics
            .record_requester_offer_delivered(group_id);
    }
    for group_id in &dropped_resolved {
        state
            .groups_diagnostics
            .record_requester_offer_resolved_drop(group_id);
    }
    for group_id in &exhausted_groups {
        state
            .groups_diagnostics
            .record_requester_offer_retry_exhausted(group_id);
    }
}

fn remove_obligation(
    by_group: &mut HashMap<String, Vec<RequesterOfferObligation>>,
    obligation: &RequesterOfferObligation,
) -> bool {
    let Some(list) = by_group.get_mut(&obligation.group_id) else {
        return false;
    };
    let before = list.len();
    list.retain(|o| o.request_id != obligation.request_id);
    let after = list.len();
    if after == 0 {
        by_group.remove(&obligation.group_id);
    }
    before != after
}

/// Test-only view of the live store.
#[cfg(test)]
pub(in crate::server) async fn requester_offer_snapshot(
    state: &AppState,
) -> Vec<RequesterOfferObligation> {
    state
        .requester_offer_outbox
        .read()
        .await
        .values()
        .flatten()
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        enforce_caps(&mut by_group);
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
        enforce_caps(&mut by_group);
        let count: usize = by_group.values().map(|l| l.len()).sum();
        assert_eq!(count, CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP);
        // The OLDEST groups' obligations were evicted: group "g0" (first
        // seen earliest) is gone, the newest survives.
        assert!(!by_group.contains_key("g0"));
        assert!(by_group.contains_key(&format!("g{}", CAUSAL_RELAY_OUTBOX_PER_DAEMON_CAP + 7)));
    }
}
