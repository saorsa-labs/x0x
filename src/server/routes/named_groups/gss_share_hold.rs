//! #1573 (ADR 0110 §3, #1508/#1533 rc13): the durable GSS share hold.
//!
//! A survivor that verified a GSS removal, ban or crypto-only exclusion
//! keeps the old group secret until the new epoch's sealed share arrives.
//! The removed member holds that old secret, so the survivor makes no new
//! group ciphertext while the transition waits
//! ([`super::GroupCiphertextHold::PendingGssRemoval`]).
//!
//! The hold has no time limit, and it survives a restart. Each waiting
//! transition is written to `gss-share-holds/<blake3(group key)>.json`
//! (0600, parent directory synced) when it parks. A restarted node loads
//! the files before its first ciphertext check, so it does not seal under
//! the old secret again. The hold ends only when the node holds a secret
//! of the transition's epoch or later (a verified key transition
//! completed). A moved head does not end it: a sibling commit can move the
//! head and keep the old secret (#1533 rc13). A file that cannot be read
//! or decoded holds its group, and a directory that cannot be read holds
//! every GSS group, until a load succeeds (fail closed).
//!
//! Only transitions whose signed commit the apply verified are written, so
//! a forged removal holds nothing. The file is local state only: it is not
//! a wire format and not an API. It carries `version`
//! ([`HOLD_FILE_VERSION`]); a file of another version is not decoded, so it
//! holds its group and is never replaced, as a damaged file is.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate as x0x;
use crate::identity::AgentId;
use crate::server::state::AppState;

use super::{
    named_group_metadata_event_commit, LogHexId, NamedGroupMetadataEvent, ParkedRoleUpdate,
};

const HOLD_DIR: &str = "gss-share-holds";

/// The in-memory side of the durable holds. Removals and bans live in
/// [`AppState::parked_gss_removals`] (the share replays them); this keeps
/// the crypto-only exclusions and the load state.
#[derive(Debug, Default)]
pub(in crate::server) struct GssShareHolds {
    /// `true` once the files are loaded in this process.
    loaded: tokio::sync::Mutex<bool>,
    /// One writer at a time, so an older snapshot never replaces a newer
    /// file.
    write: tokio::sync::Mutex<()>,
    exclusions: StdMutex<HashMap<String, Vec<ExclusionHold>>>,
    /// The hold files that exist but did not decode. Each holds its group
    /// and is never replaced by a write.
    undecodable: StdMutex<HashSet<PathBuf>>,
    /// `true` while the hold directory, or a file in it, cannot be read:
    /// every GSS group is held until a load succeeds.
    unreadable: std::sync::atomic::AtomicBool,
    /// The groups whose last write failed. A later park or hold of the
    /// group, a resend included, writes again ([`retry_unsaved`]).
    unsaved: StdMutex<HashSet<String>>,
}

/// A verified GSS crypto-only exclusion that waits for its share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExclusionHold {
    /// The head the exclusion chains from.
    parent_state_hash: String,
    /// The secret epoch the exclusion rotates to.
    secret_epoch: u64,
    /// #1533 rc19: the members that an evicted held removal or ban of this
    /// epoch, or of an earlier epoch that the cap dropped, removes
    /// ([`removes_share_actor`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeldRemoval {
    event: NamedGroupMetadataEvent,
    /// The hex agent id of the sender, for the replay.
    sender: String,
}

/// The hold file format version.
const HOLD_FILE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct HoldFile {
    version: u32,
    group_key: String,
    #[serde(default)]
    removals: Vec<HeldRemoval>,
    #[serde(default)]
    exclusions: Vec<ExclusionHold>,
}

fn hold_dir(state: &AppState) -> PathBuf {
    state.data_dir.join(HOLD_DIR)
}

fn hold_path(state: &AppState, group_key: &str) -> PathBuf {
    let name = blake3::hash(group_key.as_bytes()).to_hex().to_string();
    hold_dir(state).join(format!("{name}.json"))
}

pub(super) fn removal_epoch(event: &NamedGroupMetadataEvent) -> Option<u64> {
    match event {
        NamedGroupMetadataEvent::MemberRemoved { secret_epoch, .. }
        | NamedGroupMetadataEvent::MemberBanned { secret_epoch, .. } => *secret_epoch,
        _ => None,
    }
}

/// The member that a held removal or ban takes off the roster.
fn removal_target(event: &NamedGroupMetadataEvent) -> Option<&str> {
    match event {
        NamedGroupMetadataEvent::MemberRemoved { agent_id, .. }
        | NamedGroupMetadataEvent::MemberBanned { agent_id, .. } => Some(agent_id),
        _ => None,
    }
}

/// #1533 rc19 (Codex P1): whether a held removal or ban of `group_key` at
/// `share_epoch` or earlier removes `actor_hex`. The head stays at the
/// parent while the removal waits, so the parent roster still lists the
/// removed admin. Its share is not authorized: the verified removal's
/// result does not list it, and a key it chose must not end the hold. A
/// share of an earlier epoch is still checked on the parent roster. Call
/// [`ensure_loaded`] first.
pub(super) fn removes_share_actor(
    state: &AppState,
    group_key: &str,
    actor_hex: &str,
    share_epoch: u64,
) -> bool {
    let at_or_before = |epoch: Option<u64>| epoch.is_some_and(|epoch| epoch <= share_epoch);
    let parked = state
        .parked_gss_removals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .is_some_and(|list| {
            list.iter().any(|entry| {
                at_or_before(removal_epoch(&entry.event))
                    && removal_target(&entry.event)
                        .is_some_and(|target| target.eq_ignore_ascii_case(actor_hex))
            })
        });
    parked
        || state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_key)
            .is_some_and(|list| {
                list.iter().any(|hold| {
                    hold.secret_epoch <= share_epoch
                        && hold
                            .removed
                            .iter()
                            .any(|member| member.eq_ignore_ascii_case(actor_hex))
                })
            })
}

/// Whether a held transition to `epoch` still holds `info`: this node
/// holds no secret of that epoch or a later one. The head is not checked:
/// a sibling commit can move it and keep the old secret.
pub(super) fn holds(info: &x0x::groups::GroupInfo, epoch: Option<u64>) -> bool {
    epoch.is_some_and(|epoch| {
        epoch > info.secret_epoch || (epoch == info.secret_epoch && info.shared_secret.is_none())
    })
}

/// #1578 (Engineer ruling, 25 Oct 00:26): the head this node reports for
/// `group_key` in a catch-up answer. While this node holds no secret of a
/// held exclusion's epoch — it installed that exclusion's result keyless —
/// the report is the live hold's parent, the newest head of the chain this
/// node's secrets vouch for, never the installed result: a keyless install
/// is local fact only, it does not prove delivery of the share, and the
/// author's delivery row must stay open until the share installs (then the
/// report is the current head again, and it is share-proof). The parent of
/// the lowest live hold is reported, so a chain of keyless installs names
/// no keyless result. A superseded install releases its hold, so its head
/// is reported as before: it proves a later key exists. A node that holds
/// a secret, or is held by no exclusion, reports its current head.
pub(super) async fn reported_head(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
) -> String {
    ensure_loaded(state).await;
    let lot = state
        .gss_share_holds
        .exclusions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(held) = lot.get(group_key) else {
        return info.state_hash.clone();
    };
    // The #1578 keyless install: the head is a held exclusion's result and
    // no secret of its epoch is held. A node with a secret, or held only
    // for a later epoch (its head is not that exclusion's result), reports
    // its current head.
    let keyless = info.shared_secret.is_none()
        && held
            .iter()
            .any(|hold| hold.secret_epoch == info.secret_epoch);
    if !keyless {
        return info.state_hash.clone();
    }
    held.iter()
        .filter(|hold| holds(info, Some(hold.secret_epoch)))
        .min_by_key(|hold| hold.secret_epoch)
        .map(|hold| hold.parent_state_hash.clone())
        .unwrap_or_else(|| info.state_hash.clone())
}

/// Whether a parked removal or ban, or a held crypto-only exclusion, still
/// holds new ciphertext for `group_key`. There is no time limit: only a
/// secret of the held epoch, or a later one, ends a hold. Call
/// [`ensure_loaded`] first.
pub(super) fn withholds(state: &AppState, group_key: &str, info: &x0x::groups::GroupInfo) -> bool {
    if info.secure_plane != x0x::mls::SecureGroupPlane::TreeKem
        && (state
            .gss_share_holds
            .unreadable
            .load(std::sync::atomic::Ordering::SeqCst)
            || state
                .gss_share_holds
                .undecodable
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains(&hold_path(state, group_key)))
    {
        return true;
    }
    let removal = state
        .parked_gss_removals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .is_some_and(|list| {
            list.iter()
                .any(|entry| holds(info, removal_epoch(&entry.event)))
        });
    removal
        || state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_key)
            .is_some_and(|list| list.iter().any(|hold| holds(info, Some(hold.secret_epoch))))
}

/// Load the durable holds once per process, before the first ciphertext
/// check, park or replay. A file that cannot be read stays on disk and is
/// logged; it is never replaced by a write.
pub(super) async fn ensure_loaded(state: &AppState) {
    let mut loaded = state.gss_share_holds.loaded.lock().await;
    if *loaded {
        return;
    }
    let dir = hold_dir(state);
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // No holds saved: a load that succeeds.
            state
                .gss_share_holds
                .unreadable
                .store(false, std::sync::atomic::Ordering::SeqCst);
            *loaded = true;
            return;
        }
        Err(error) => {
            // Not loaded: every GSS group is held, and the next check
            // tries again.
            state
                .gss_share_holds
                .unreadable
                .store(true, std::sync::atomic::Ordering::SeqCst);
            tracing::error!(
                "#1573 GSS share holds not read from {}: {error}",
                dir.display()
            );
            return;
        }
    };
    let mut files = Vec::new();
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => files.push(entry.path()),
            Ok(None) => break,
            Err(error) => {
                state
                    .gss_share_holds
                    .unreadable
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                tracing::error!(
                    "#1573 GSS share holds not listed in {}: {error}",
                    dir.display()
                );
                return;
            }
        }
    }
    for path in files {
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let file = match tokio::fs::read(&path)
            .await
            .map(|bytes| decode_hold_file(&bytes))
        {
            Ok(Ok(file)) => file,
            Ok(Err(error)) => {
                // Its group stays held: the file may hold a removal.
                tracing::error!(
                    "#1573 GSS share hold {} is not readable; its group makes no ciphertext until the file is repaired or removed and the daemon restarts: {error}",
                    path.display()
                );
                state
                    .gss_share_holds
                    .undecodable
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(path);
                continue;
            }
            Err(error) => {
                state
                    .gss_share_holds
                    .unreadable
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                tracing::error!("#1573 GSS share hold {} not read: {error}", path.display());
                return;
            }
        };
        absorb(state, file);
    }
    state
        .gss_share_holds
        .unreadable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    *loaded = true;
}

fn decode_hold_file(bytes: &[u8]) -> Result<HoldFile, String> {
    let file: HoldFile = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if file.version != HOLD_FILE_VERSION {
        return Err(format!(
            "unsupported hold file version {} (expected {HOLD_FILE_VERSION})",
            file.version
        ));
    }
    Ok(file)
}

fn absorb(state: &AppState, file: HoldFile) {
    if !file.removals.is_empty() {
        let mut lot = state
            .parked_gss_removals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let list = lot.entry(file.group_key.clone()).or_default();
        for held in file.removals {
            let Some(sender) = hex::decode(&held.sender)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            else {
                continue;
            };
            let hash = named_group_metadata_event_commit(&held.event)
                .map(|commit| commit.state_hash.clone());
            if list.iter().any(|entry| {
                named_group_metadata_event_commit(&entry.event)
                    .map(|commit| commit.state_hash.clone())
                    == hash
            }) {
                continue;
            }
            list.push(ParkedRoleUpdate {
                event: held.event,
                sender: AgentId(sender),
                parked_at: Instant::now(),
            });
        }
    }
    if !file.exclusions.is_empty() {
        let mut lot = state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let list = lot.entry(file.group_key).or_default();
        for hold in file.exclusions {
            match list.iter_mut().find(|kept| {
                kept.parent_state_hash == hold.parent_state_hash
                    && kept.secret_epoch == hold.secret_epoch
            }) {
                Some(kept) => merge_removed(kept, hold.removed),
                None => list.push(hold),
            }
        }
    }
}

/// Write the group's holds as memory holds them now (or remove the file
/// when none is left).
pub(super) async fn persist(state: &AppState, group_key: &str) -> std::io::Result<()> {
    ensure_loaded(state).await;
    let _writer = state.gss_share_holds.write.lock().await;
    let removals: Vec<HeldRemoval> = state
        .parked_gss_removals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .map(|list| {
            list.iter()
                .map(|entry| HeldRemoval {
                    event: entry.event.clone(),
                    sender: hex::encode(entry.sender.0),
                })
                .collect()
        })
        .unwrap_or_default();
    let exclusions = state
        .gss_share_holds
        .exclusions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .cloned()
        .unwrap_or_default();
    let path = hold_path(state, group_key);
    if state
        .gss_share_holds
        .undecodable
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(&path)
    {
        return Err(std::io::Error::other(
            "an undecodable hold file is kept, not replaced",
        ));
    }
    if removals.is_empty() && exclusions.is_empty() {
        return match tokio::fs::remove_file(&path).await {
            Ok(()) => super::sync_parent_dir_for_path(&path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
    }
    let file = HoldFile {
        version: HOLD_FILE_VERSION,
        group_key: group_key.to_string(),
        removals,
        exclusions,
    };
    let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    crate::storage::save_private_bytes_to(&path, bytes)
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    super::sync_parent_dir_for_path(&path)
}

/// Write the group's holds, and log a failed write. Memory still holds the
/// transition, so this process keeps withholding. The group is marked
/// unsaved, so the next park or hold of it, a resend included, writes again
/// ([`retry_unsaved`]); only a restart before a good write loses it.
pub(super) async fn persist_logged(state: &AppState, group_key: &str) {
    let result = persist(state, group_key).await;
    let mut unsaved = state
        .gss_share_holds
        .unsaved
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match result {
        Ok(()) => {
            unsaved.remove(group_key);
        }
        Err(error) => {
            unsaved.insert(group_key.to_string());
            tracing::error!(
                group_id = %LogHexId::group(group_key),
                "#1573 GSS share hold not saved; sends stay withheld in this process: {error}"
            );
        }
    }
}

/// Write the group's holds again if its last write failed. A resend of a
/// held transition is not held twice, but it does retry the write.
pub(super) async fn retry_unsaved(state: &AppState, group_key: &str) {
    let unsaved = state
        .gss_share_holds
        .unsaved
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains(group_key);
    if unsaved {
        persist_logged(state, group_key).await;
    }
}

/// Add `hold` to the group's exclusion holds. At the cap the hold of the
/// lowest epoch goes: a hold of a later epoch withholds whenever a hold of
/// an earlier one does ([`holds`]), so the group stays held as before.
fn push_exclusion(state: &AppState, group_key: &str, hold: ExclusionHold) -> bool {
    let mut lot = state
        .gss_share_holds
        .exclusions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let list = lot.entry(group_key.to_string()).or_default();
    // One hold per parent and epoch; a second one adds its removed members.
    if let Some(kept) = list.iter_mut().find(|kept| {
        kept.parent_state_hash == hold.parent_state_hash && kept.secret_epoch == hold.secret_epoch
    }) {
        let before = kept.removed.len();
        merge_removed(kept, hold.removed);
        return kept.removed.len() != before;
    }
    list.push(hold);
    while list.len() > super::PARKED_ROLE_UPDATE_CAP {
        let lowest = list
            .iter()
            .enumerate()
            .min_by_key(|(_, kept)| kept.secret_epoch)
            .map(|(at, _)| at);
        match lowest {
            Some(at) => {
                let dropped = list.remove(at);
                // #1533 rc19: the removed members move to the next lowest
                // hold. Its epoch is later, so it still ends no hold when
                // they seal a share.
                if let Some(next) = list.iter_mut().min_by_key(|kept| kept.secret_epoch) {
                    merge_removed(next, dropped.removed);
                }
            }
            None => break,
        }
    }
    true
}

/// Add `members` to `hold`'s removed members, once each.
fn merge_removed(hold: &mut ExclusionHold, members: Vec<String>) {
    for member in members {
        if !hold.removed.contains(&member) {
            hold.removed.push(member);
        }
    }
}

/// A parked removal or ban left the full parked list: keep its hold as an
/// exclusion hold of its epoch, so the cap never ends a hold. Its replay is
/// lost; the containment is not. The caller writes the file.
pub(super) fn keep_evicted_removal(
    state: &AppState,
    group_key: &str,
    event: &NamedGroupMetadataEvent,
) {
    let parent = named_group_metadata_event_commit(event)
        .and_then(|commit| commit.prev_state_hash.clone())
        .unwrap_or_default();
    if let Some(secret_epoch) = removal_epoch(event) {
        push_exclusion(
            state,
            group_key,
            ExclusionHold {
                parent_state_hash: parent,
                secret_epoch,
                removed: removal_target(event)
                    .map(str::to_string)
                    .into_iter()
                    .collect(),
            },
        );
    }
}

/// A verified GSS crypto-only exclusion from `parent_state_hash` waits
/// for the share of `secret_epoch`: hold new ciphertext until it installs.
pub(super) async fn hold_exclusion(
    state: &AppState,
    group_key: &str,
    parent_state_hash: &str,
    secret_epoch: u64,
) {
    ensure_loaded(state).await;
    // #1508 rc17 (#1533 rc16): added under the GSS publication gate held
    // exclusively, as a parked removal is (`park_gss_removal_for_share`).
    let gss_gate = state.gss_publication_gate.write().await;
    let added = push_exclusion(
        state,
        group_key,
        ExclusionHold {
            parent_state_hash: parent_state_hash.to_string(),
            secret_epoch,
            removed: Vec::new(),
        },
    );
    drop(gss_gate);
    if added {
        persist_logged(state, group_key).await;
    } else {
        retry_unsaved(state, group_key).await;
    }
}

/// Drop the group's exclusion holds that no longer hold `info` (a secret of
/// their epoch or a later one is installed), such as an evicted removal's
/// hold after its key installed, or #1578's keyless install hold after the
/// share it awaits installed. Returns whether a hold was dropped. The
/// caller writes the file.
pub(super) fn prune_exclusions(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
) -> bool {
    let mut lot = state
        .gss_share_holds
        .exclusions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(list) = lot.get_mut(group_key) else {
        return false;
    };
    let before = list.len();
    list.retain(|hold| holds(info, Some(hold.secret_epoch)));
    let dropped = list.len() != before;
    if list.is_empty() {
        lot.remove(group_key);
    }
    dropped
}

/// Whether the group has an exclusion hold in memory. A share that installs
/// with no removal parked still prunes the holds it ends (#1578). Call
/// [`ensure_loaded`] first.
pub(super) fn holds_exclusions(state: &AppState, group_key: &str) -> bool {
    state
        .gss_share_holds
        .exclusions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains_key(group_key)
}

/// The exclusion installed with its secret at `secret_epoch`: its hold,
/// and every older one, ends.
pub(super) async fn release_exclusions(state: &AppState, group_key: &str, secret_epoch: u64) {
    ensure_loaded(state).await;
    let removed = {
        let mut lot = state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(list) = lot.get_mut(group_key) else {
            return;
        };
        let before = list.len();
        list.retain(|hold| hold.secret_epoch > secret_epoch);
        let removed = list.len() != before;
        if list.is_empty() {
            lot.remove(group_key);
        }
        removed
    };
    if removed {
        persist_logged(state, group_key).await;
    }
}

/// The group is gone from this node: drop its holds and their files.
pub(super) async fn forget_group<'a>(
    state: &AppState,
    aliases: impl IntoIterator<Item = &'a String> + Clone,
) {
    ensure_loaded(state).await;
    let _writer = state.gss_share_holds.write.lock().await;
    {
        let mut lot = state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for alias in aliases.clone() {
            lot.remove(alias);
        }
    }
    {
        let mut lot = state
            .parked_gss_removals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for alias in aliases.clone() {
            lot.remove(alias);
        }
    }
    for alias in aliases {
        let path = hold_path(state, alias);
        if tokio::fs::remove_file(&path).await.is_ok() {
            let _ = super::sync_parent_dir_for_path(&path);
        }
    }
}

#[cfg(test)]
pub(in crate::server) mod test_seam {
    use super::*;

    /// A restart: memory loses every parked removal and held exclusion,
    /// and the next check loads the files again.
    pub(in crate::server) async fn simulate_restart(state: &AppState) {
        state
            .parked_gss_removals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        state
            .gss_share_holds
            .undecodable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        state
            .gss_share_holds
            .unsaved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *state.gss_share_holds.loaded.lock().await = false;
    }

    /// Age every parked removal past the old ten-minute limit.
    pub(in crate::server) fn age_parked_removals(state: &AppState, by: std::time::Duration) {
        let mut lot = state
            .parked_gss_removals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for list in lot.values_mut() {
            for entry in list.iter_mut() {
                if let Some(earlier) = entry.parked_at.checked_sub(by) {
                    entry.parked_at = earlier;
                }
            }
        }
    }

    pub(in crate::server) fn held_exclusions(state: &AppState, group_key: &str) -> usize {
        state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_key)
            .map_or(0, Vec::len)
    }

    pub(in crate::server) fn hold_path_for(state: &AppState, group_key: &str) -> PathBuf {
        hold_path(state, group_key)
    }

    pub(in crate::server) fn hold_file_exists(state: &AppState, group_key: &str) -> bool {
        hold_path(state, group_key).exists()
    }
}
