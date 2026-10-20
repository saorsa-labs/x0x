//! ADR 0110 (slice S4 of ADR 0088): the daemon side of revocation
//! eviction, designated first.
//!
//! The pure model (rows, phases, typed waits, designation, timing) lives in
//! [`x0x::groups::eviction`]. This module owns:
//!
//! - §1 intake: it drains the queue that the revocation choke point in
//!   `lib.rs` feeds after `verify_and_insert` returns `Ok(true)` (and the
//!   startup load), and it scans the loaded rosters for self-leave and
//!   certificate-expiry triggers. Each trigger becomes an obligation keyed
//!   by (stable group ID, target agent ID).
//! - Completion: a row completes only when the verified roster and crypto
//!   state exclude the target.
//!
//! The revocation-set lock is always released before this module takes a
//! group or persistence lock (§1).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate as x0x;
use crate::server::state::AppState;
use x0x::groups::eviction::{
    EvictionKey, EvictionTrigger, IntakeOutcome, ObligationStore, RowBudget, S4Timing,
    TerminationCause, VerifiedAgentRevocation,
};
use x0x::groups::{GroupInfo, GroupMemberState};

/// The worker's idle re-check interval. Budgets and expiry checks run at
/// least this often; intake wakes the worker at once.
const S4_WORKER_TICK: Duration = Duration::from_secs(1);

/// S4 runtime state held on [`AppState`].
pub(in crate::server) struct S4Runtime {
    /// The timing values (PENDING MEASUREMENT defaults, see
    /// [`S4Timing`]).
    pub(in crate::server) timing: S4Timing,
    /// Random per-process boot identity (§2, §5).
    boot_id: [u8; 16],
    inner: tokio::sync::Mutex<S4Inner>,
}

#[derive(Default)]
struct S4Inner {
    store: ObligationStore,
    /// In-boot monotonic budgets, keyed like the rows.
    budgets: HashMap<EvictionKey, RowBudget>,
    /// The revocation-set generation at the last full reconciliation.
    reconciled_generation: Option<u64>,
}

impl Default for S4Runtime {
    fn default() -> Self {
        Self::new(S4Timing::default())
    }
}

impl S4Runtime {
    /// A runtime with the given timing values.
    pub(in crate::server) fn new(timing: S4Timing) -> Self {
        let mut boot_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut boot_id);
        Self {
            timing,
            boot_id,
            inner: tokio::sync::Mutex::new(S4Inner::default()),
        }
    }
}

/// The S4 worker. Runs until the task is aborted at shutdown.
pub(in crate::server) async fn run_revocation_eviction_worker(state: Arc<AppState>) {
    if x0x::groups::eviction::S4_TIMING_PENDING_MEASUREMENT {
        let timing = state.revocation_evictions.timing;
        tracing::info!(
            designated_window_ms = timing.designated_window.as_millis() as u64,
            completion_bound_ms = timing.completion_bound.as_millis() as u64,
            fallback_stagger_ms = timing.fallback_stagger.as_millis() as u64,
            restart_sync_wait_ms = timing.restart_sync_wait.as_millis() as u64,
            "ADR 0110 S4 timing values are provisional (pending the W3-H measurement)"
        );
    }
    let notify = state.agent.s4_revocation_intake().notified();
    loop {
        revocation_eviction_pass(&state).await;
        tokio::select! {
            () = notify.notified() => {}
            () = tokio::time::sleep(S4_WORKER_TICK) => {}
        }
    }
}

/// One worker pass: intake, scan, reconcile.
pub(in crate::server) async fn revocation_eviction_pass(state: &Arc<AppState>) {
    let revocations = collect_verified_agent_revocations(state).await;
    let groups = snapshot_groups(state).await;
    let leaves = snapshot_retained_leaves(state, &groups).await;
    let now_unix_ms = now_unix_ms();
    let now_unix = now_unix_ms / 1000;
    let runtime = &state.revocation_evictions;
    let mut inner = runtime.inner.lock().await;
    let boot_id = runtime.boot_id;
    let mut created = Vec::new();
    for (key, trigger, incarnation) in derive_triggers(&groups, &leaves, &revocations, now_unix) {
        let outcome =
            inner
                .store
                .intake(&key, trigger, incarnation.as_deref(), now_unix_ms, boot_id);
        if matches!(outcome, IntakeOutcome::Created | IntakeOutcome::Reopened) {
            created.push(key);
        }
    }
    let now = Instant::now();
    for key in created {
        inner
            .budgets
            .insert(key, RowBudget::resume(Duration::ZERO, now));
    }
    reconcile_completion(&mut inner.store, &groups, &leaves, now_unix_ms);
    // Rows loaded from an earlier boot resume their saved budget.
    let rows: Vec<(EvictionKey, u64)> = inner
        .store
        .rows()
        .filter(|row| row.phase.is_open())
        .map(|row| (row.key(), row.elapsed_budget_ms))
        .collect();
    for (key, saved_ms) in rows {
        inner
            .budgets
            .entry(key)
            .or_insert_with(|| RowBudget::resume(Duration::from_millis(saved_ms), now));
    }
    let open: std::collections::BTreeSet<EvictionKey> = inner
        .store
        .rows()
        .filter(|row| row.phase.is_open())
        .map(|row| row.key())
        .collect();
    inner.budgets.retain(|key, _| open.contains(key));
}

/// Drain the intake queue and, when needed, rescan the whole revocation
/// set. Only records that this node's own set holds are kept: the hook
/// already verified them, and the check guards against a stale queue.
async fn collect_verified_agent_revocations(state: &AppState) -> Vec<VerifiedAgentRevocation> {
    let intake = state.agent.s4_revocation_intake();
    let (mut items, reconcile_all) = intake.drain();
    let revocation_set = state.agent.revocation_set();
    let set = revocation_set.read().await;
    let generation = set.generation();
    let full = {
        let inner = state.revocation_evictions.inner.lock().await;
        reconcile_all || inner.reconciled_generation != Some(generation)
    };
    if full {
        for record in set.all_records() {
            if let x0x::revocation::RevokedSubject::Agent(agent) = &record.subject {
                items.push(VerifiedAgentRevocation {
                    target: *agent.as_bytes(),
                    record_hash: record.record_hash(),
                    record_bytes: bincode::serialize(&record).unwrap_or_default(),
                    from_startup_load: false,
                });
            }
        }
    }
    items.retain(|item| set.contains_hash(&item.record_hash));
    drop(set);
    if full {
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .reconciled_generation = Some(generation);
    }
    items
}

async fn snapshot_groups(state: &AppState) -> Vec<GroupInfo> {
    state
        .named_groups
        .read()
        .await
        .values()
        .filter(|info| !info.withdrawn)
        .cloned()
        .collect()
}

/// Retained TreeKEM leaves per stable group ID: the agent IDs whose leaf
/// is still in this node's ratchet tree, with the tree epoch. A group whose
/// tree is busy is skipped for this pass (`None`), never read as empty.
/// The agents with a leaf in one tree, and the tree epoch.
type TrackedLeaves = (Vec<[u8; 32]>, u64);

#[derive(Default)]
struct RetainedLeaves {
    by_group: HashMap<String, Option<TrackedLeaves>>,
}

impl RetainedLeaves {
    fn tracks(&self, stable_group_id: &str, agent: &[u8; 32]) -> Option<bool> {
        match self.by_group.get(stable_group_id) {
            Some(Some((tracked, _))) => Some(tracked.contains(agent)),
            Some(None) => None,
            None => Some(false),
        }
    }

    fn epoch(&self, stable_group_id: &str) -> Option<u64> {
        match self.by_group.get(stable_group_id) {
            Some(Some((_, epoch))) => Some(*epoch),
            _ => None,
        }
    }

    fn known(&self, stable_group_id: &str) -> bool {
        !matches!(self.by_group.get(stable_group_id), Some(None))
    }
}

async fn snapshot_retained_leaves(state: &AppState, groups: &[GroupInfo]) -> RetainedLeaves {
    let mut leaves = RetainedLeaves::default();
    let trees = state.treekem_groups.read().await;
    for info in groups {
        if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem {
            continue;
        }
        let stable = info.stable_group_id().to_string();
        let tree = trees
            .get(&info.mls_group_id)
            .or_else(|| trees.get(&stable))
            .cloned();
        let Some(tree) = tree else {
            continue;
        };
        let entry = match tree.try_lock() {
            Ok(group) => {
                let tracked = info
                    .members_v2
                    .values()
                    .filter_map(|member| super::parse_agent_id_hex(&member.agent_id).ok())
                    .filter(|agent| group.tracks_member(agent))
                    .map(|agent| *agent.as_bytes())
                    .collect();
                Some((tracked, group.epoch()))
            }
            Err(_) => None,
        };
        leaves.by_group.insert(stable, entry);
    }
    leaves
}

fn is_seated(state: GroupMemberState) -> bool {
    matches!(state, GroupMemberState::Active | GroupMemberState::Pending)
}

fn owner_certified(info: &GroupInfo) -> bool {
    matches!(
        info.policy.admission,
        x0x::groups::policy::GroupAdmission::OwnerCertified(_)
    )
}

/// §1 and §1a: the triggers this pass observes, with the target's current
/// incarnation (its KeyPackage hash).
fn derive_triggers(
    groups: &[GroupInfo],
    leaves: &RetainedLeaves,
    revocations: &[VerifiedAgentRevocation],
    now_unix: u64,
) -> Vec<(EvictionKey, EvictionTrigger, Option<String>)> {
    let mut out = Vec::new();
    let mut revoked_by_target: HashMap<[u8; 32], Vec<&VerifiedAgentRevocation>> = HashMap::new();
    for item in revocations {
        revoked_by_target.entry(item.target).or_default().push(item);
    }
    for info in groups {
        let stable = info.stable_group_id();
        for member in info.members_v2.values() {
            let Ok(agent) = super::parse_agent_id_hex(&member.agent_id) else {
                continue;
            };
            let target = *agent.as_bytes();
            let retained_leaf = leaves.tracks(stable, &target).unwrap_or(false);
            let seated = is_seated(member.state);
            let incarnation = member.treekem_key_package_hash.clone();
            // §1: an Agent-subject revocation creates work where the target
            // has a seat or a retained cryptographic leaf.
            if seated || retained_leaf {
                if let Some(records) = revoked_by_target.get(&target) {
                    for record in records {
                        out.push((
                            EvictionKey::new(stable, target),
                            EvictionTrigger::AgentRevocation {
                                record_hash: record.record_hash,
                                record_bytes: record.record_bytes.clone(),
                            },
                            incarnation.clone(),
                        ));
                    }
                }
            }
            // §1: a verified, chained self-leave applied to the roster
            // (including through catch-up) whose leaf is still retained.
            let self_left = member.state == GroupMemberState::Removed
                && member.removed_by.as_deref() == Some(member.agent_id.as_str());
            if self_left && retained_leaf {
                out.push((
                    EvictionKey::new(stable, target),
                    EvictionTrigger::SelfLeave {
                        commit_hash: info.state_hash.clone(),
                    },
                    incarnation.clone(),
                ));
            }
            // §1a: expiry of the committed certificate of an Active seat in
            // an OwnerCertified group, on this node's own clock + τ.
            if member.state == GroupMemberState::Active && owner_certified(info) {
                if let Some((digest, not_after)) = selected_certificate_expiry(member) {
                    if x0x::groups::eviction::own_expiry_trigger_due(not_after, now_unix) {
                        out.push((
                            EvictionKey::new(stable, target),
                            EvictionTrigger::CertificateExpiry {
                                certificate_digest: digest,
                                not_after,
                            },
                            incarnation.clone(),
                        ));
                    }
                }
            }
        }
    }
    out
}

/// §1a: the selected certificate is the one the committed roster binds to
/// the seat — its embedded bytes when they match the committed digest.
/// Returns its digest and `not_after`; `None` when it never expires or the
/// bytes are missing.
fn selected_certificate_expiry(member: &x0x::groups::GroupMember) -> Option<(String, u64)> {
    let cert = member.certificate.as_ref()?;
    let digest = x0x::groups::owner_cert::certificate_digest_hex(cert);
    if member
        .certificate_digest
        .as_deref()
        .is_some_and(|committed| committed != digest)
    {
        return None;
    }
    cert.not_after().map(|not_after| (digest, not_after))
}

/// Re-derive completion from the verified roster and crypto state (§1,
/// D128). A row completes only when the target holds no seat and, in a
/// TreeKEM group, no retained leaf. A group that is withdrawn or deleted
/// terminates its rows; a group this node no longer holds ends local
/// retention.
fn reconcile_completion(
    store: &mut ObligationStore,
    groups: &[GroupInfo],
    leaves: &RetainedLeaves,
    now_unix_ms: u64,
) {
    let by_stable: HashMap<&str, &GroupInfo> = groups
        .iter()
        .map(|info| (info.stable_group_id(), info))
        .collect();
    let open: Vec<EvictionKey> = store
        .rows()
        .filter(|row| row.phase.is_open())
        .map(|row| row.key())
        .collect();
    let mut gone_groups = std::collections::BTreeSet::new();
    for key in open {
        let Some(info) = by_stable.get(key.stable_group_id.as_str()) else {
            gone_groups.insert(key.stable_group_id.clone());
            continue;
        };
        let target_hex = hex::encode(key.target);
        let member = info.members_v2.get(&target_hex);
        let seated = member.is_some_and(|member| is_seated(member.state));
        let stable = key.stable_group_id.as_str();
        if seated {
            // §1a/D135: an expiry-only row ends when the committed
            // certificate changed to an unexpired one (a rebind).
            if let Some(member) = member {
                let row_digests = store
                    .get(&key)
                    .map(|row| row.expiry_only().then(|| row.expired_certificates.clone()));
                if let Some(Some(expired)) = row_digests {
                    let now_unix = now_unix_ms / 1000;
                    let renewed = selected_certificate_expiry(member).map_or(
                        member.certificate.is_some(),
                        |(digest, not_after)| {
                            !expired.contains_key(&digest)
                                && !x0x::groups::eviction::own_expiry_trigger_due(
                                    not_after, now_unix,
                                )
                        },
                    );
                    if renewed {
                        store.terminate(&key, TerminationCause::CertificateValid);
                    }
                }
            }
            continue;
        }
        if info.secure_plane == x0x::mls::SecureGroupPlane::TreeKem {
            if !leaves.known(stable) {
                // The tree was busy; decide on a later pass.
                continue;
            }
            if leaves.tracks(stable, &key.target).unwrap_or(true) {
                continue;
            }
        }
        store.complete(
            &key,
            Some(info.state_hash.clone()),
            leaves.epoch(stable).or(Some(info.secret_epoch)),
            now_unix_ms,
        );
    }
    for stable in gone_groups {
        store.forget_group(&stable);
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_leaves_unknown_group_is_not_tracked() {
        let leaves = RetainedLeaves::default();
        assert_eq!(leaves.tracks("g", &[1; 32]), Some(false));
        assert!(leaves.known("g"));
    }

    #[test]
    fn busy_tree_is_unknown_not_empty() {
        let mut leaves = RetainedLeaves::default();
        leaves.by_group.insert("g".into(), None);
        assert_eq!(leaves.tracks("g", &[1; 32]), None);
        assert!(!leaves.known("g"));
    }
}
