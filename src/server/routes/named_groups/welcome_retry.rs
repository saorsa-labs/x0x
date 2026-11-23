//! #2202: the joiner-side retry for a verified own seal whose TreeKEM
//! Welcome could not be fetched.
//!
//! Before this, the joiner's own `MemberAdded` (or `JoinRequestApproved`)
//! with a Welcome reference was rejected when the Welcome fetch failed, the
//! join attempt then timed out, and its finalizer removed the pending stub.
//! The authority kept the seat `Active`, the joiner kept no group (404) and
//! nothing asked again, so a transient transport failure became permanent.
//!
//! Now the failed fetch leaves a typed record ([`RetryRecord`]):
//!
//! - the attempt's timeout keeps the stub ([`owns_stub`]) and the worker
//!   makes it durable, so it is an ADR 0107 `UnseatedJoinRemnant`;
//! - after the attempt ends, the worker re-arms the join with ADR 0107's
//!   fetch-only re-arm ([`super::rearm_sealed_unconfirmed_join_core`]),
//!   pinned to the device that sealed the add, with a bounded back-off;
//! - the record ends when the joiner holds its keys (`seated`), or as
//!   `lost` when the authority refuses, the row is no longer a remnant, the
//!   re-arm budget is spent, or the staged Welcome's lifetime
//!   (`PENDING_WELCOME_TTL`, 10 minutes from staging) has passed since the
//!   first failure. A `lost` record names the exit: an admin removes the
//!   agent and invites it again;
//! - a redeemed invite starts a new join attempt and forgets the record
//!   ([`forget`]).
//!
//! The record is kept in `<data_dir>/welcome-retries.json` (format
//! `x0x.welcome-retry`, version 1), so a restart resumes it. Nothing new
//! goes on the wire: a re-arm sends the existing join-result `FetchRequest`,
//! and the authority serves only under ADR 0107's current-roster guard.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate as x0x;
use crate::server::state::AppState;
use x0x::identity::AgentId;
use x0x::logging::LogHexId;

/// The file that holds the records, under the daemon's data directory.
pub(super) const WELCOME_RETRY_FILE: &str = "welcome-retries.json";
/// The format name in the file.
const WELCOME_RETRY_FORMAT: &str = "x0x.welcome-retry";
/// The only format version this build reads and writes.
const WELCOME_RETRY_VERSION: u32 = 1;
/// The worker tick.
const TICK: Duration = Duration::from_secs(2);
/// At most this many automatic re-arms per record.
pub(super) const MAX_REARMS: u32 = 6;
/// The wait before re-arm `n` (0-based), counted from the end of the
/// attempt before it. The last value repeats.
const REARM_BACKOFF_MS: [u64; 4] = [5_000, 15_000, 30_000, 60_000];
/// The longest `last_error` kept.
const MAX_ERROR_LEN: usize = 256;
/// The exit a `lost` record names.
pub(super) const LOST_REMEDY: &str =
    "an admin removes this agent from the group and invites it again";

/// Where a record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RetryState {
    /// The worker re-arms the join after each attempt ends.
    Retrying,
    /// No further re-arm; the record names why and the exit.
    Lost,
}

/// One group's retry. Serialized as one entry of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RetryRecord {
    pub(super) stable_group_id: String,
    pub(super) local_group_key: String,
    /// The device that sealed the add and staged the Welcome: the attempt's
    /// pinned inviter. A re-arm is pinned to it (ADR 0107).
    pub(super) sealer_agent_id: String,
    pub(super) inviter_public_key_b64: String,
    pub(super) invite_fingerprint: String,
    pub(super) welcome_id: String,
    /// Wall-clock ms of the first failed fetch for this Welcome.
    pub(super) first_failed_at_ms: u64,
    pub(super) rearms: u32,
    pub(super) next_rearm_at_ms: u64,
    pub(super) state: RetryState,
    pub(super) last_error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) lost_reason: Option<String>,
}

impl RetryRecord {
    fn expires_at_ms(&self) -> u64 {
        self.first_failed_at_ms
            .saturating_add(super::PENDING_WELCOME_TTL.as_millis() as u64)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RetryFileV1 {
    format: String,
    version: u32,
    records: Vec<RetryRecord>,
}

/// The runtime held in `AppState`.
#[derive(Debug, Default)]
pub(in crate::server) struct WelcomeRetries {
    /// Keyed by stable group id. A plain mutex, never held across an await.
    records: StdMutex<HashMap<String, RetryRecord>>,
    /// Serialises file writes (and the one load).
    writer: tokio::sync::Mutex<()>,
    loaded: AtomicBool,
    /// The file on disk could not be read: it is left as it is and never
    /// overwritten (ADR 0085 rule 4); records live in memory only.
    fault: AtomicBool,
}

impl WelcomeRetries {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, RetryRecord>> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn snapshot(&self) -> Vec<RetryRecord> {
        self.lock().values().cloned().collect()
    }
}

fn retry_file(state: &AppState) -> PathBuf {
    state.data_dir.join(WELCOME_RETRY_FILE)
}

fn local_hex(state: &AppState) -> String {
    hex::encode(state.agent.agent_id().as_bytes())
}

fn truncate_error(error: &str) -> String {
    let mut end = error.len().min(MAX_ERROR_LEN);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_string()
}

fn backoff_ms(rearms: u32) -> u64 {
    let index = (rearms as usize).min(REARM_BACKOFF_MS.len() - 1);
    REARM_BACKOFF_MS[index]
}

fn decode_agent_id(hex_id: &str) -> Option<AgentId> {
    let bytes: [u8; 32] = hex::decode(hex_id).ok()?.try_into().ok()?;
    Some(AgentId(bytes))
}

/// Load the file once. An unreadable file or an unknown format or version
/// sets the fault: the file is left untouched (ADR 0085 rule 4) and the
/// records of this run live in memory only.
async fn ensure_loaded(state: &AppState) {
    let runtime = &state.welcome_retries;
    if runtime.loaded.load(Ordering::Acquire) {
        return;
    }
    let _writer = runtime.writer.lock().await;
    if runtime.loaded.load(Ordering::Acquire) {
        return;
    }
    let path = retry_file(state);
    match tokio::fs::read(&path).await {
        Ok(bytes) => match serde_json::from_slice::<RetryFileV1>(&bytes) {
            Ok(file)
                if file.format == WELCOME_RETRY_FORMAT && file.version == WELCOME_RETRY_VERSION =>
            {
                let mut records = runtime.lock();
                for record in file.records {
                    records
                        .entry(record.stable_group_id.clone())
                        .or_insert(record);
                }
            }
            Ok(file) => {
                runtime.fault.store(true, Ordering::Release);
                tracing::error!(
                    path = %path.display(),
                    format = %file.format,
                    version = file.version,
                    "#2202: unknown Welcome-retry file format; it is left untouched and not rewritten"
                );
            }
            Err(error) => {
                runtime.fault.store(true, Ordering::Release);
                tracing::error!(
                    path = %path.display(),
                    %error,
                    "#2202: unreadable Welcome-retry file; it is left untouched and not rewritten"
                );
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            runtime.fault.store(true, Ordering::Release);
            tracing::error!(
                path = %path.display(),
                %error,
                "#2202: cannot read the Welcome-retry file; it is not rewritten"
            );
        }
    }
    runtime.loaded.store(true, Ordering::Release);
}

/// Write every record durably, or remove the file when none is left. Inside
/// an uncommitted ADR 0094 upgrade trial no new file is created (the
/// records then live in memory only). Returns whether the bytes are
/// durable.
async fn persist(state: &AppState) -> bool {
    let runtime = &state.welcome_retries;
    if runtime.fault.load(Ordering::Acquire) {
        return false;
    }
    let _writer = runtime.writer.lock().await;
    let path = retry_file(state);
    let mut records = runtime.snapshot();
    records.sort_by(|a, b| a.stable_group_id.cmp(&b.stable_group_id));
    if records.is_empty() {
        return match tokio::fs::remove_file(&path).await {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "#2202: cannot remove the empty Welcome-retry file");
                false
            }
        };
    }
    if !super::revocation_eviction::host_commit_gate_open(state)
        && !matches!(tokio::fs::try_exists(&path).await, Ok(true))
    {
        tracing::info!("#2202: no new Welcome-retry file before ADR 0094 host commit; the retry lives in memory");
        return false;
    }
    let file = RetryFileV1 {
        format: WELCOME_RETRY_FORMAT.to_string(),
        version: WELCOME_RETRY_VERSION,
        records,
    };
    let bytes = match serde_json::to_vec_pretty(&file) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "#2202: cannot encode the Welcome-retry file");
            return false;
        }
    };
    match super::revocation_eviction::write_bytes_durably(&path, &bytes, None).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "#2202: Welcome-retry file write failed");
            false
        }
    }
}

/// The own-seal Welcome fetch failed (both seal arms call this, after
/// every check before the fetch passed). A record is kept only for an
/// invite join with a live attempt whose pinned inviter is the device that
/// staged the Welcome (`welcome_ref.source`): only that device can serve a
/// re-arm (ADR 0107). A record for the same Welcome keeps its first-failure
/// time; a different Welcome (a new seal) replaces it.
pub(super) async fn note_own_seal_unfetched(
    state: &AppState,
    local_group_key: &str,
    stable_group_id: &str,
    welcome_ref: &super::WelcomeRef,
    error: &str,
) {
    let local = local_hex(state);
    let key = super::join_result_key(stable_group_id, &local);
    let attempt = state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&key)
        .map(|attempt| {
            (
                attempt.invite_fingerprint.clone(),
                attempt.inviter_public_key_b64.clone(),
                attempt.local_group_key.clone(),
            )
        });
    let Some((invite_fingerprint, inviter_public_key_b64, attempt_key)) = attempt else {
        tracing::debug!(
            group_id = %LogHexId::group(stable_group_id),
            "#2202: own seal's Welcome not fetched outside a live join attempt; no retry record"
        );
        return;
    };
    let pinned = super::expected_join_result_inviter(state, &key);
    if !pinned.is_some_and(|pinned| pinned.eq_ignore_ascii_case(&welcome_ref.source)) {
        tracing::info!(
            group_id = %LogHexId::group(stable_group_id),
            source = %LogHexId::agent(&welcome_ref.source),
            "#2202: the Welcome's stager is not this attempt's pinned inviter; no retry record"
        );
        return;
    }
    ensure_loaded(state).await;
    let now = super::now_millis_u64();
    let local_group_key = if attempt_key.is_empty() {
        local_group_key.to_string()
    } else {
        attempt_key
    };
    {
        let mut records = state.welcome_retries.lock();
        match records.get_mut(stable_group_id) {
            Some(record) if record.welcome_id == welcome_ref.welcome_id => {
                record.last_error = truncate_error(error);
                record.local_group_key = local_group_key;
            }
            _ => {
                records.insert(
                    stable_group_id.to_string(),
                    RetryRecord {
                        stable_group_id: stable_group_id.to_string(),
                        local_group_key,
                        sealer_agent_id: welcome_ref.source.to_ascii_lowercase(),
                        inviter_public_key_b64,
                        invite_fingerprint,
                        welcome_id: welcome_ref.welcome_id.clone(),
                        first_failed_at_ms: now,
                        rearms: 0,
                        next_rearm_at_ms: now.saturating_add(backoff_ms(0)),
                        state: RetryState::Retrying,
                        last_error: truncate_error(error),
                        lost_reason: None,
                    },
                );
                tracing::warn!(
                    group_id = %LogHexId::group(stable_group_id),
                    welcome_id = %LogHexId::new("welcome", &welcome_ref.welcome_id),
                    "#2202: own seal verified but its Welcome could not be fetched; the join is kept and will be re-armed"
                );
            }
        }
    }
    persist(state).await;
}

/// Whether a `retrying` record owns the stub at `local_group_key`: the
/// join attempt's timeout then keeps the stub (the finalizer reads this
/// under its locks; it takes no lock and never awaits).
pub(super) fn owns_stub(state: &AppState, local_group_key: &str) -> bool {
    state.welcome_retries.lock().values().any(|record| {
        record.state == RetryState::Retrying && record.local_group_key == local_group_key
    })
}

/// A redeemed invite starts a new join attempt for the group (D64): its
/// record, `retrying` or `lost`, is forgotten.
pub(super) async fn forget(state: &AppState, stable_group_id: &str) {
    ensure_loaded(state).await;
    let removed = state
        .welcome_retries
        .lock()
        .remove(stable_group_id)
        .is_some();
    if removed {
        tracing::info!(
            group_id = %LogHexId::group(stable_group_id),
            "#2202: a new join attempt began; the Welcome retry is forgotten"
        );
        persist(state).await;
    }
}

/// The record for `stable_group_id`, if any (tests and status).
pub(super) async fn record_for(state: &AppState, stable_group_id: &str) -> Option<RetryRecord> {
    ensure_loaded(state).await;
    state.welcome_retries.lock().get(stable_group_id).cloned()
}

/// The `welcome_retry` object on join-status and `GET /groups/:id`
/// (`null` when there is no record).
pub(super) async fn status_json(state: &AppState, stable_group_id: &str) -> serde_json::Value {
    let Some(record) = record_for(state, stable_group_id).await else {
        return serde_json::Value::Null;
    };
    let mut value = serde_json::json!({
        "state": record.state,
        "welcome_id": record.welcome_id,
        "sealer_agent_id": record.sealer_agent_id,
        "first_failed_at_ms": record.first_failed_at_ms,
        "expires_at_ms": record.expires_at_ms(),
        "rearms": record.rearms,
        "max_rearms": MAX_REARMS,
        "last_error": record.last_error,
    });
    match record.state {
        RetryState::Retrying => {
            value["next_rearm_at_ms"] = serde_json::json!(record.next_rearm_at_ms);
        }
        RetryState::Lost => {
            value["reason"] = serde_json::json!(record.lost_reason);
            value["remedy"] = serde_json::json!(LOST_REMEDY);
        }
    }
    value
}

/// The worker: loads the file, then ticks until shutdown.
pub(in crate::server) async fn run_welcome_retry_worker(state: Arc<AppState>) {
    ensure_loaded(&state).await;
    let mut interval = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            biased;
            () = state.shutdown_started.cancelled() => break,
            _ = interval.tick() => {}
        }
        tick_at(&state, super::now_millis_u64()).await;
    }
}

/// What one tick decided for one record.
enum Step {
    Keep,
    Forget,
    Seated,
    Lost(&'static str),
    Rearm,
}

/// Whether this node holds its TreeKEM keys for the group: an Active seat
/// and an installed TreeKEM group (an Active seat alone is not keys on the
/// TreeKEM plane, A08 amendment of 18 Nov 2026).
async fn holds_keys(state: &AppState, key: &str, info: &x0x::groups::GroupInfo) -> bool {
    if !info.has_active_member(&local_hex(state)) {
        return false;
    }
    let treekem = state.treekem_groups.read().await;
    treekem.contains_key(key)
        || treekem.contains_key(info.mls_group_id.as_str())
        || treekem.contains_key(info.stable_group_id())
}

fn live_attempt(state: &AppState, stable_group_id: &str) -> bool {
    let key = super::join_result_key(stable_group_id, &local_hex(state));
    state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains_key(&key)
}

fn refused(state: &AppState, key: &str) -> bool {
    state
        .last_join_outcomes
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(key)
        .is_some_and(|outcome| outcome.outcome == "refused")
}

/// Make a retrying record's stub durable, so a later timeout or a restart
/// keeps it (the same step S3 takes for an unserved seal).
async fn make_stub_durable(state: &AppState, key: &str) {
    let pending = state
        .pending_join_stubs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(key);
    if !pending {
        return;
    }
    let lock = super::group_membership_lock(state, key).await;
    let _membership_guard = lock.lock().await;
    let Some(stub) = state.named_groups.read().await.get(key).cloned() else {
        return;
    };
    if !matches!(
        super::persist_named_group_info(state, key, stub).await,
        Ok(super::AtomicWriteOutcome::Durable)
    ) {
        tracing::warn!(group_id = %LogHexId::group(key), "#2202: the retrying joiner's stub is not durable yet");
    }
}

async fn decide(state: &AppState, record: &RetryRecord, now_ms: u64) -> Step {
    if record.state == RetryState::Lost {
        // A lost record stays (status) until the joiner has keys or a new
        // attempt forgets it.
        let info = state
            .named_groups
            .read()
            .await
            .get(&record.local_group_key)
            .cloned();
        return match info {
            Some(info) if holds_keys(state, &record.local_group_key, &info).await => Step::Seated,
            _ => Step::Keep,
        };
    }
    let Some(info) = state
        .named_groups
        .read()
        .await
        .get(&record.local_group_key)
        .cloned()
    else {
        // The row is gone: a new join cleared it, or the group was removed.
        return Step::Forget;
    };
    if holds_keys(state, &record.local_group_key, &info).await {
        return Step::Seated;
    }
    if live_attempt(state, &record.stable_group_id) {
        return Step::Keep;
    }
    if refused(state, &record.local_group_key) {
        return Step::Lost("authority_refused");
    }
    if super::classify_not_member_join_row(&info, &local_hex(state))
        != super::NotMemberJoinRow::UnseatedJoinRemnant
    {
        return Step::Lost("row_not_retryable");
    }
    if now_ms >= record.expires_at_ms() {
        return Step::Lost("welcome_lifetime_passed");
    }
    if record.rearms >= MAX_REARMS {
        return Step::Lost("rearms_exhausted");
    }
    if now_ms < record.next_rearm_at_ms {
        return Step::Keep;
    }
    Step::Rearm
}

/// One pass over the records at wall-clock `now_ms`.
pub(super) async fn tick_at(state: &Arc<AppState>, now_ms: u64) {
    ensure_loaded(state).await;
    let records = state.welcome_retries.snapshot();
    for record in records {
        if record.state == RetryState::Retrying {
            make_stub_durable(state, &record.local_group_key).await;
        }
        match decide(state, &record, now_ms).await {
            Step::Keep => {
                if record.state == RetryState::Retrying
                    && live_attempt(state, &record.stable_group_id)
                {
                    // The back-off counts from the end of the live attempt.
                    let wait = now_ms.saturating_add(backoff_ms(record.rearms));
                    if let Some(current) = state
                        .welcome_retries
                        .lock()
                        .get_mut(&record.stable_group_id)
                    {
                        current.next_rearm_at_ms = current.next_rearm_at_ms.max(wait);
                    }
                }
            }
            Step::Forget => {
                state.welcome_retries.lock().remove(&record.stable_group_id);
                persist(state).await;
            }
            Step::Seated => {
                state.welcome_retries.lock().remove(&record.stable_group_id);
                state
                    .groups_diagnostics
                    .record_welcome_retry_seated(&record.stable_group_id);
                tracing::info!(
                    group_id = %LogHexId::group(&record.stable_group_id),
                    rearms = record.rearms,
                    "#2202: the Welcome retry ended seated with keys"
                );
                persist(state).await;
            }
            Step::Lost(reason) => {
                if let Some(current) = state
                    .welcome_retries
                    .lock()
                    .get_mut(&record.stable_group_id)
                {
                    current.state = RetryState::Lost;
                    current.lost_reason = Some(reason.to_string());
                }
                state
                    .groups_diagnostics
                    .record_welcome_retry_lost(&record.stable_group_id);
                tracing::warn!(
                    group_id = %LogHexId::group(&record.stable_group_id),
                    reason,
                    rearms = record.rearms,
                    remedy = LOST_REMEDY,
                    "#2202: the Welcome retry ended without keys"
                );
                persist(state).await;
            }
            Step::Rearm => rearm(state, &record, now_ms).await,
        }
    }
}

/// Re-arm under the membership lock, after the same checks again.
async fn rearm(state: &Arc<AppState>, record: &RetryRecord, now_ms: u64) {
    let Some(inviter) = decode_agent_id(&record.sealer_agent_id) else {
        if let Some(current) = state
            .welcome_retries
            .lock()
            .get_mut(&record.stable_group_id)
        {
            current.state = RetryState::Lost;
            current.lost_reason = Some("sealer_id_invalid".to_string());
        }
        persist(state).await;
        return;
    };
    let lock = super::group_membership_lock(state, &record.local_group_key).await;
    let guard = lock.lock().await;
    let Some(info) = state
        .named_groups
        .read()
        .await
        .get(&record.local_group_key)
        .cloned()
    else {
        return;
    };
    let still_retrying = state
        .welcome_retries
        .lock()
        .get(&record.stable_group_id)
        .is_some_and(|current| {
            current.state == RetryState::Retrying && current.welcome_id == record.welcome_id
        });
    if !still_retrying
        || live_attempt(state, &record.stable_group_id)
        || holds_keys(state, &record.local_group_key, &info).await
        || super::classify_not_member_join_row(&info, &local_hex(state))
            != super::NotMemberJoinRow::UnseatedJoinRemnant
    {
        return;
    }
    let attempt_id = super::rearm_sealed_unconfirmed_join_core(
        state,
        guard,
        &record.local_group_key,
        info,
        super::RearmPin {
            inviter_hex: record.sealer_agent_id.clone(),
            inviter_public_key_b64: record.inviter_public_key_b64.clone(),
            invite_fingerprint: record.invite_fingerprint.clone(),
            inviter,
        },
        true,
    )
    .await;
    let rearms = {
        let mut records = state.welcome_retries.lock();
        let Some(current) = records.get_mut(&record.stable_group_id) else {
            return;
        };
        current.rearms = current.rearms.saturating_add(1);
        current.next_rearm_at_ms = now_ms.saturating_add(backoff_ms(current.rearms));
        current.rearms
    };
    state
        .groups_diagnostics
        .record_welcome_retry_rearm(&record.stable_group_id);
    tracing::info!(
        group_id = %LogHexId::group(&record.stable_group_id),
        attempt = %LogHexId::new("attempt", &attempt_id),
        rearms,
        "#2202: re-armed the join to fetch the original Welcome again"
    );
    persist(state).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_then_holds() {
        assert_eq!(backoff_ms(0), 5_000);
        assert_eq!(backoff_ms(1), 15_000);
        assert_eq!(backoff_ms(3), 60_000);
        assert_eq!(backoff_ms(40), 60_000);
    }

    #[test]
    fn errors_are_truncated_on_a_char_boundary() {
        let long = "é".repeat(MAX_ERROR_LEN);
        let cut = truncate_error(&long);
        assert!(cut.len() <= MAX_ERROR_LEN);
        assert!(long.starts_with(&cut));
    }

    /// ADR 0085 rule 4: a file of a version this build does not know is
    /// left untouched and never rewritten. Inert: an offline agent.
    #[tokio::test]
    async fn an_unknown_file_version_is_left_untouched_and_never_rewritten() -> anyhow::Result<()> {
        let (state, _dir) = super::super::tests::secure_endpoint_test_state().await?;
        let path = retry_file(&state);
        let bytes = br#"{"format":"x0x.welcome-retry","version":2,"records":[]}"#.to_vec();
        tokio::fs::write(&path, &bytes).await?;
        ensure_loaded(&state).await;
        assert!(state.welcome_retries.fault.load(Ordering::Acquire));
        state.welcome_retries.lock().insert(
            "aa".into(),
            RetryRecord {
                stable_group_id: "aa".into(),
                local_group_key: "aa".into(),
                sealer_agent_id: "bb".into(),
                inviter_public_key_b64: String::new(),
                invite_fingerprint: String::new(),
                welcome_id: "cc".into(),
                first_failed_at_ms: 1,
                rearms: 0,
                next_rearm_at_ms: 1,
                state: RetryState::Retrying,
                last_error: String::new(),
                lost_reason: None,
            },
        );
        assert!(!persist(&state).await, "a faulted file is not written");
        assert_eq!(tokio::fs::read(&path).await?, bytes);
        Ok(())
    }

    #[test]
    fn the_file_round_trips_and_names_its_format() -> anyhow::Result<()> {
        let record = RetryRecord {
            stable_group_id: "aa".into(),
            local_group_key: "bb".into(),
            sealer_agent_id: "cc".into(),
            inviter_public_key_b64: "dd".into(),
            invite_fingerprint: "ee".into(),
            welcome_id: "ff".into(),
            first_failed_at_ms: 1,
            rearms: 2,
            next_rearm_at_ms: 3,
            state: RetryState::Lost,
            last_error: "x".into(),
            lost_reason: Some("rearms_exhausted".into()),
        };
        let file = RetryFileV1 {
            format: WELCOME_RETRY_FORMAT.into(),
            version: WELCOME_RETRY_VERSION,
            records: vec![record.clone()],
        };
        let bytes = serde_json::to_vec(&file)?;
        let text = String::from_utf8(bytes.clone())?;
        assert!(text.contains("\"format\":\"x0x.welcome-retry\""));
        assert!(text.contains("\"state\":\"lost\""));
        let back: RetryFileV1 = serde_json::from_slice(&bytes)?;
        assert_eq!(back.records, vec![record]);
        Ok(())
    }
}
