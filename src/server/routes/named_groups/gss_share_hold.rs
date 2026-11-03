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
//! through the shared S3/S4 durable writer (0600 from creation, content
//! and directory synced) when it parks. A restarted node loads
//! the files before its first ciphertext check, so it does not seal under
//! the old secret again. The hold ends only when the node holds a secret
//! of the transition's epoch or later (a verified key transition
//! completed). A moved head does not end it: a sibling commit can move the
//! head and keep the old secret (#1533 rc13). A file that cannot be read
//! or decoded holds its group, and a directory that cannot be read holds
//! every GSS group, until a load succeeds (fail closed).
//!
//! #1766: the file also keeps the sender of an installed share whose epoch
//! no head commits yet, bound to that secret. A file can hold only that
//! record; it holds no ciphertext. A crypto-only exclusion's hold ends at
//! such a secret only when the exclusion's actor sealed it.
//!
//! #1775: a head commit pins a secret value only when it committed with
//! one. A #1578 keyless install commits its epoch with no secret, so the
//! file keeps a mark of it: the mark holds the group's ciphertext and
//! keeps that epoch's first installed secret replaceable until the
//! exclusion's own actor seals one (or a later epoch commits). A secret
//! of a later epoch that the head does not commit (#1775 item 2) ends no
//! wait: no verified transition completed. A pre-#1771 hold file carries
//! no actor list; its actors are unknown, so no secret that a commit
//! does not pin ends its hold (#1775 item 3).
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
    /// #1766: per group, the sender of the installed share of an epoch
    /// that no head commits yet ([`share_sent_by`]). Durable in the hold
    /// file, so a restart between the share and its crypto-only exclusion
    /// keeps it.
    share_senders: StdMutex<HashMap<String, ShareSender>>,
    /// #1775: per group, the mark of a #1578 keyless commit
    /// ([`KeylessMark`]). Durable in the hold file.
    keyless: StdMutex<HashMap<String, KeylessMark>>,
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
    /// #1766: the lower-case hex actors of the crypto-only exclusions that
    /// wait on this hold. An uncommitted secret of its epoch ends the hold
    /// only when one of them sealed it ([`hold_live`]). `None` is a hold
    /// from a pre-#1771 file (#1775 item 3): its actors are unknown, so no
    /// secret that a commit does not pin ends it, until the frame retries
    /// and adds its actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actors: Option<Vec<String>>,
}

/// #1766: the sender of an installed share whose epoch no head commits yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShareSender {
    secret_epoch: u64,
    /// The lower-case hex agent id of the sender.
    sender: String,
    /// [`secret_tag`] of the secret that the sender sealed. The key and
    /// this record are two writes, so the record names the key it is for.
    #[serde(default)]
    secret: String,
}

/// #1766: binds a [`ShareSender`] to one secret. The secret itself is in
/// the group state on the same disk, so the tag reveals nothing new.
fn secret_tag(secret: &[u8]) -> String {
    hex::encode(blake3::derive_key("x0x gss share sender v1", secret))
}

/// #1775 item 4: the mark of a #1578 keyless install. The head it moved
/// commits its epoch with no secret, so it pins no secret value: the mark
/// keeps that epoch's installed secret replaceable — and its group's new
/// ciphertext held — until the exclusion's own actor seals a share of it
/// ([`note_share_sender`]), or a head commits a later epoch
/// ([`prune_share_sender`]). The mark claims exactly its own epoch: a
/// share of a later unpinned epoch is not its waiting actor's key, and
/// no hold of the later epoch exists to claim it. It is durable, and the #1663 key
/// republication keeps it: that release ends the hold of a secretless
/// survivor, but the first admin's share that reaches its re-keyed seat
/// is still not the actor's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeylessMark {
    secret_epoch: u64,
    /// The lower-case hex actor of the exclusion that installed keyless.
    actor: String,
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
    /// #1766: holds nothing; an older reader ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    share_sender: Option<ShareSender>,
    /// #1775: holds nothing; an older reader ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyless: Option<KeylessMark>,
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

/// #1578 (David's ruling, 28 Oct 02:09 GMT; Engineer ruling, 28 Oct
/// 09:35 GMT): the head this node claims for a group in a catch-up
/// answer, from the narrow inputs its caller copied under the groups
/// read lock. `None` exactly while the node is a keyless GSS survivor
/// of an encrypted group: the policy is `MlsEncrypted` (a SignedPublic
/// group is GSS-plane by default and holds no secret and no seat KEM
/// key by design — its members are not keyless survivors), the group's
/// secrets are GSS-delivered, the node holds no secret of its saved
/// head's epoch, and its own roster seat carries no KEM public key —
/// the #1578 keyless install. Such a node can never identify a share
/// sealed to its seat, so its install is local fact only and must never
/// converge an author's delivery row: no peer sees convergence evidence
/// from it until a secret of that epoch installs, and a chain of
/// keyless installs claims no head at all. The claim is derived from
/// the group state itself, never from the hold file: a hold write that
/// fails, and the restart after it, cannot turn a keyless install into
/// a head claim (the installed GSS head keeps implying its key). Every
/// other responder — one with a secret, one whose waiting keeps the old
/// secret, one whose own seat still carries the KEM key though no
/// secret of the saved head's epoch remains (a superseded intermediate
/// install), a SignedPublic member, an encrypted-group joiner that
/// still waits for
/// its welcome share (its own seat is not an Active keyless seat: it is
/// not seated yet, or seated with the KEM key its `MemberJoined`
/// published), a member of any other plane (a TreeKEM joiner holds
/// heads with no GSS secret and no seat KEM key by design, so the
/// keyless marker is meaningless there), and a responder that does not
/// know the group — claims its saved head, exactly as on main.
/// Disclosed residue: an encrypted-group member whose own-view roster
/// lost the KEM key before any share installed omits while in that
/// state — the same class as the ruled keyless state (no key of the
/// epoch, no seat key), converging nothing.
pub(super) fn reported_head(
    gss_plane: bool,
    encrypted: bool,
    saved_head: &str,
    has_secret: bool,
    own_seat_keyless: bool,
) -> Option<String> {
    if gss_plane && encrypted && !has_secret && own_seat_keyless {
        None
    } else {
        Some(saved_head.to_string())
    }
}

/// Whether a parked removal or ban, or a held crypto-only exclusion, still
/// holds new ciphertext for `group_key`. There is no time limit: only a
/// secret of the held epoch, or a later one, ends a hold. #1775: a secret
/// that no verified commit pins ends none — an unsealed-epoch share
/// installed over the wait (item 2), or the first share after a keyless
/// commit (item 4), keeps the group held until the waiting actor's own
/// share installs. Call [`ensure_loaded`] first.
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
    let sent = installed_share_sender(state, group_key, info);
    // #1775 item 1 (the parked-list half): a parked removal or ban also
    // keeps holding under an installed secret that no commit pins, unless
    // the removal's own sender sealed it. The actor's re-delivery from
    // another survivor (#1660) carries the same secret, so this waits for
    // the value, not the courier: once the head commits the epoch, the
    // secret is pinned and the wait ends.
    let removal = state
        .parked_gss_removals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .is_some_and(|list| {
            list.iter().any(|entry| {
                removal_epoch(&entry.event).is_some_and(|epoch| {
                    holds(info, Some(epoch))
                        || (info.shared_secret.is_some()
                            && secret_unpinned(state, group_key, info)
                            && !sent.as_deref().is_some_and(|sent| {
                                sent.eq_ignore_ascii_case(&hex::encode(entry.sender.0))
                            }))
                })
            })
        });
    // #1775 item 4: after a keyless commit the mark holds the group while
    // a secret of that epoch is installed and its sender is not the
    // exclusion's actor — also once the #1663 republication released the
    // hold itself.
    let keyless = state
        .gss_share_holds
        .keyless
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .is_some_and(|mark| {
            info.secret_epoch == mark.secret_epoch
                && info.shared_secret.is_some()
                && !sent
                    .as_deref()
                    .is_some_and(|sent| sent.eq_ignore_ascii_case(&mark.actor))
        });
    removal
        || keyless
        || state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_key)
            .is_some_and(|list| {
                list.iter()
                    .any(|hold| hold_live(state, group_key, info, hold, sent.as_deref()))
            })
}

/// #1775 item 4: whether the secret of its local epoch that `info` holds
/// is pinned by a verified commit. A commit pins a secret value only when
/// it committed with one: the head binding an epoch pins that epoch's
/// value, except after a #1578 keyless install, whose durable mark keeps
/// the epoch unpinned until its actor's share installs. A sealed share
/// that raised the local epoch above what the head commits (#1775 item 2)
/// is not pinned either. Call [`ensure_loaded`] first.
pub(super) fn secret_unpinned(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
) -> bool {
    x0x::groups::crypto_exclusion::committed_secret_epoch(info) < info.secret_epoch
        || state
            .gss_share_holds
            .keyless
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_key)
            .is_some_and(|mark| mark.secret_epoch == info.secret_epoch)
}

/// #1766/#1775: whether `hold` still holds `info`, when `sent` sealed the
/// installed secret ([`installed_share_sender`]). As [`holds`], except
/// that a secret that no verified commit pins — of the hold's epoch from
/// another sender, or of a later epoch that the head does not commit
/// (#1775 item 2: no verified transition completed) — ends a crypto-only
/// exclusion's hold only when one of its actors sealed it. A hold whose
/// actors are unknown (a pre-#1771 file, #1775 item 3) is ended by no
/// secret that a commit does not pin.
fn hold_live(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
    hold: &ExclusionHold,
    sent: Option<&str>,
) -> bool {
    if holds(info, Some(hold.secret_epoch)) {
        return true;
    }
    // A secret of the hold's epoch or a later one is installed. It ends
    // the hold only when a commit pins it and a recorded actor sealed it.
    info.shared_secret.is_some()
        && secret_unpinned(state, group_key, info)
        && match &hold.actors {
            Some(actors) => {
                !actors.is_empty()
                    && !sent.is_some_and(|sent| {
                        actors.iter().any(|actor| actor.eq_ignore_ascii_case(sent))
                    })
            }
            None => true,
        }
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
    let mut entries = match crate::w3h_inline::fs::read_dir(&dir).await {
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
        let file = match crate::w3h_inline::fs::read(&path)
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
    if let Some(sender) = file.share_sender {
        state
            .gss_share_holds
            .share_senders
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(file.group_key.clone(), sender);
    }
    if let Some(mark) = file.keyless {
        state
            .gss_share_holds
            .keyless
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(file.group_key.clone(), mark);
    }
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
        for mut hold in file.exclusions {
            // #1775 item 3: a hold with removed members is an evicted
            // removal's containment — actorless by design, not unknown —
            // so it keeps the old rule; a crypto-only exclusion's hold
            // from a pre-#1771 file has no removed members and unknown
            // actors. #1775 review round 2: a pre-#1771 file that merged
            // an evicted removal into an exclusion hold of the same
            // parent and epoch reads the same way — the `removed` gate
            // bounds that exposure to that one shape.
            if hold.actors.is_none() && !hold.removed.is_empty() {
                hold.actors = Some(Vec::new());
            }
            match list.iter_mut().find(|kept| {
                kept.parent_state_hash == hold.parent_state_hash
                    && kept.secret_epoch == hold.secret_epoch
            }) {
                Some(kept) => {
                    merge_removed(kept, hold.removed);
                    // #1775: a merge keeps every actor; an unknown actor
                    // list stays unknown.
                    merge_actors(&mut kept.actors, hold.actors);
                }
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
    let share_sender = state
        .gss_share_holds
        .share_senders
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .cloned();
    let keyless = state
        .gss_share_holds
        .keyless
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .cloned();
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
    if removals.is_empty() && exclusions.is_empty() && share_sender.is_none() && keyless.is_none() {
        return match crate::w3h_inline::fs::remove_file(&path).await {
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
        share_sender,
        keyless,
    };
    let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
    if let Some(parent) = path.parent() {
        crate::w3h_inline::fs::create_dir_all(parent).await?;
    }
    // #1533 rc22: the shared S3/S4 writer (ADR 0110 §5 write barrier):
    // the temporary file is created 0600 before any byte, its content is
    // synced before the rename, and the directory is synced after it.
    super::revocation_eviction::write_bytes_durably(&path, &bytes, None).await
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
    // One hold per parent and epoch; a second one adds its removed members
    // and actors.
    if let Some(kept) = list.iter_mut().find(|kept| {
        kept.parent_state_hash == hold.parent_state_hash && kept.secret_epoch == hold.secret_epoch
    }) {
        let before = kept.removed.len() + kept.actors.as_ref().map_or(0, Vec::len);
        merge_removed(kept, hold.removed);
        // #1775 item 3: a live re-park knows its actor, so a non-empty
        // list replaces an unknown one loaded from a pre-#1771 file (an
        // empty list — an evicted removal — would turn "unknown" into
        // "known none" and fail open); two known lists union.
        let mut actors = std::mem::take(&mut kept.actors);
        if actors.is_none() {
            if hold
                .actors
                .as_ref()
                .is_some_and(|actors| !actors.is_empty())
            {
                actors = hold.actors;
            }
        } else {
            merge_actors(&mut actors, hold.actors);
        }
        kept.actors = actors;
        return kept.removed.len() + kept.actors.as_ref().map_or(0, Vec::len) != before;
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
                // they seal a share. #1775: the dropped hold's waiting
                // actors do not move: an actor of the dropped epoch may
                // not end a later epoch's wait (that would fail open).
                // The dropped exclusion's frame retries and re-parks its
                // hold, so its actor check returns with it.
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
        if !hold
            .removed
            .iter()
            .any(|kept| kept.eq_ignore_ascii_case(&member))
        {
            hold.removed.push(member);
        }
    }
}

/// #1775: fold `more` into `kept`'s actor list. A known list keeps every
/// actor once; an unknown list (a pre-#1771 hold file carries none, and a
/// merge with one cannot know it) stays unknown, so no secret that a
/// commit does not pin ends the merged hold.
fn merge_actors(kept: &mut Option<Vec<String>>, more: Option<Vec<String>>) {
    match (kept.take(), more) {
        (Some(mut actors), Some(more)) => {
            for actor in more {
                if !actors.iter().any(|kept| kept.eq_ignore_ascii_case(&actor)) {
                    actors.push(actor);
                }
            }
            *kept = Some(actors);
        }
        (known, more) => *kept = known.and(more),
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
                // #1775: an evicted removal waits for no actor's share;
                // its actors are known to be none.
                actors: Some(Vec::new()),
            },
        );
    }
}

/// A verified GSS crypto-only exclusion by `actor_hex` from
/// `parent_state_hash` waits for the share of `secret_epoch`: hold new
/// ciphertext until it installs.
pub(super) async fn hold_exclusion(
    state: &AppState,
    group_key: &str,
    parent_state_hash: &str,
    secret_epoch: u64,
    actor_hex: &str,
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
            actors: Some(vec![actor_hex.to_ascii_lowercase()]),
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
/// share it awaits installed. #1766: a crypto-only exclusion's hold stays
/// while another sender's secret of its epoch is installed
/// ([`hold_live`]), and a share sender whose epoch the head now commits
/// goes. Returns whether anything was dropped. The caller writes the file.
pub(super) fn prune_exclusions(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
) -> bool {
    let sent = installed_share_sender(state, group_key, info);
    let mut lot = state
        .gss_share_holds
        .exclusions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dropped = lot.get_mut(group_key).is_some_and(|list| {
        let before = list.len();
        list.retain(|hold| hold_live(state, group_key, info, hold, sent.as_deref()));
        list.len() != before
    });
    if lot.get(group_key).is_some_and(Vec::is_empty) {
        lot.remove(group_key);
    }
    drop(lot);
    prune_share_sender(state, group_key, info) || dropped
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

/// #1766/#1775: `sender_hex` sealed `secret`, the share of `secret_epoch`
/// that just installed over `info`. The sender is kept, durably and bound
/// to `secret`, only while no verified commit pins the secret's value: a
/// crypto-only exclusion of that epoch keeps the secret only from its own
/// actor ([`share_sent_by`]), and a keyless commit's mark settles when
/// its actor's share installs ([`KeylessMark`]).
pub(super) async fn note_share_sender(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
    secret_epoch: u64,
    sender_hex: &str,
    secret: &[u8],
) {
    ensure_loaded(state).await;
    let mark = state
        .gss_share_holds
        .keyless
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .cloned();
    let committed = x0x::groups::crypto_exclusion::committed_secret_epoch(info);
    // #1775: an unsealed epoch is not pinned; so is the marked epoch of a
    // keyless commit, whose head bound the epoch with no secret.
    let uncommitted = secret_epoch > committed
        || mark
            .as_ref()
            .is_some_and(|mark| mark.secret_epoch == secret_epoch);
    let settled = mark.as_ref().is_some_and(|mark| {
        mark.secret_epoch == secret_epoch && mark.actor.eq_ignore_ascii_case(sender_hex)
    });
    let changed = {
        let mut senders = state
            .gss_share_holds
            .share_senders
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // #1775: a settled keyless epoch is pinned by its commit, so it
        // keeps no sender record either — the file can go.
        let keep = uncommitted && !(settled && secret_epoch <= committed);
        let mut changed = if keep {
            let sender = ShareSender {
                secret_epoch,
                sender: sender_hex.to_ascii_lowercase(),
                secret: secret_tag(secret),
            };
            senders.insert(group_key.to_string(), sender.clone()) != Some(sender)
        } else {
            senders.remove(group_key).is_some()
        };
        if settled {
            changed |= state
                .gss_share_holds
                .keyless
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(group_key)
                .is_some();
        }
        changed
    };
    if changed {
        persist_logged(state, group_key).await;
    }
}

/// #1775 item 4: the head that this exclusion just installed commits its
/// epoch with no secret, so it pins no secret value. The durable mark
/// keeps the epoch's first installed secret replaceable, and the group's
/// new ciphertext held, until the exclusion's own actor seals a share of
/// it.
pub(super) async fn note_keyless_commit(
    state: &AppState,
    group_key: &str,
    secret_epoch: u64,
    actor_hex: &str,
) {
    ensure_loaded(state).await;
    let changed = {
        let mut lot = state
            .gss_share_holds
            .keyless
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mark = KeylessMark {
            secret_epoch,
            actor: actor_hex.to_ascii_lowercase(),
        };
        lot.insert(group_key.to_string(), mark.clone()) != Some(mark)
    };
    if changed {
        persist_logged(state, group_key).await;
    }
}

/// #1775 item 4 (claude review round 2): the keyless commit did not
/// happen after all — its apply refused, or nothing was staged — so the
/// mark written ahead of it goes. A staged-but-undurable install keeps
/// it: that head moved in memory.
pub(super) async fn forget_keyless_commit(state: &AppState, group_key: &str, secret_epoch: u64) {
    ensure_loaded(state).await;
    let removed = {
        let mut lot = state
            .gss_share_holds
            .keyless
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        lot.get(group_key)
            .is_some_and(|mark| mark.secret_epoch == secret_epoch)
            && lot.remove(group_key).is_some()
    };
    if removed {
        persist_logged(state, group_key).await;
    }
}

/// #1766/#1775: drop the group's share sender once `info`'s head pins its
/// epoch (or a later one) — a keyless-marked epoch stays unpinned until
/// its actor's share installs. A head that commits a later epoch also
/// ends the keyless mark of an earlier one. Returns whether anything was
/// dropped; the caller writes the file.
fn prune_share_sender(state: &AppState, group_key: &str, info: &x0x::groups::GroupInfo) -> bool {
    let committed = x0x::groups::crypto_exclusion::committed_secret_epoch(info);
    let marked = state
        .gss_share_holds
        .keyless
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .map(|mark| mark.secret_epoch);
    let mut changed = false;
    if marked.is_some_and(|epoch| epoch < committed) {
        changed |= state
            .gss_share_holds
            .keyless
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(group_key)
            .is_some();
    }
    let mut lot = state
        .gss_share_holds
        .share_senders
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if lot
        .get(group_key)
        .is_some_and(|kept| kept.secret_epoch <= committed && marked != Some(kept.secret_epoch))
    {
        lot.remove(group_key);
        return true;
    }
    changed
}

/// #1766: [`prune_share_sender`], and write the file when it changed.
pub(super) async fn forget_committed_share_sender(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
) {
    ensure_loaded(state).await;
    if prune_share_sender(state, group_key, info) {
        persist_logged(state, group_key).await;
    }
}

/// #1766: the lower-case hex sender of the secret that `info` holds,
/// when the kept record names that exact secret and its epoch. A record
/// left by a crash between a replacing key write and its record write
/// names another secret, so the sender is unknown. Call [`ensure_loaded`]
/// first.
fn installed_share_sender(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
) -> Option<String> {
    let tag = secret_tag(info.shared_secret.as_deref()?);
    state
        .gss_share_holds
        .share_senders
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(group_key)
        .filter(|kept| kept.secret_epoch == info.secret_epoch && kept.secret == tag)
        .map(|kept| kept.sender.clone())
}

/// #1766: whether `sender_hex` sealed the secret that `info` holds. An
/// unknown sender (another install path, or a record that names another
/// secret) is not `sender_hex`. Call [`ensure_loaded`] first.
pub(super) fn share_sent_by(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
    sender_hex: &str,
) -> bool {
    installed_share_sender(state, group_key, info)
        .is_some_and(|sent| sent.eq_ignore_ascii_case(sender_hex))
}

/// #1766/#1775: whether a share of `secret_epoch` from `sender_hex` may
/// replace the secret of the same epoch that `info` holds. Only a secret
/// that no verified commit pins can go, only for a different sender, and
/// only while a verified transition of that epoch still waits: a
/// crypto-only exclusion's hold, a parked removal or ban (#1775 item 1),
/// or a keyless commit's mark (#1775 item 4). The waiting transition
/// keeps a secret only from its own actor, so without this its actor's
/// share could never install. Once the actor's secret is in, or a commit
/// pins the value, no other share replaces it. Call [`ensure_loaded`]
/// first.
pub(super) fn replaces_uncommitted_secret(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
    sender_hex: &str,
    secret_epoch: u64,
) -> bool {
    let sent = installed_share_sender(state, group_key, info);
    secret_epoch == info.secret_epoch
        && secret_unpinned(state, group_key, info)
        && !sent
            .as_deref()
            .is_some_and(|sent| sent.eq_ignore_ascii_case(sender_hex))
        && (state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_key)
            .is_some_and(|list| {
                list.iter().any(|hold| {
                    hold.secret_epoch == secret_epoch
                        && hold_live(state, group_key, info, hold, sent.as_deref())
                })
            })
            || state
                .parked_gss_removals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(group_key)
                .is_some_and(|list| {
                    list.iter().any(|entry| {
                        removal_epoch(&entry.event) == Some(secret_epoch)
                            // The removal's own sender's secret is in: no
                            // other share replaces it, exactly as for a
                            // hold's actor.
                            && !sent.as_deref().is_some_and(|sent| {
                                sent.eq_ignore_ascii_case(&hex::encode(entry.sender.0))
                            })
                    })
                })
            || state
                .gss_share_holds
                .keyless
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(group_key)
                .is_some_and(|mark| mark.secret_epoch == secret_epoch))
}

/// The exclusion installed with its secret at `secret_epoch`: its hold,
/// and every older one, ends. #1775: the key that installed pins the
/// epoch, so a keyless mark of it (or of an older one) ends too.
pub(super) async fn release_exclusions(state: &AppState, group_key: &str, secret_epoch: u64) {
    ensure_loaded(state).await;
    let mut released = false;
    {
        let mut lot = state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(list) = lot.get_mut(group_key) {
            let before = list.len();
            list.retain(|hold| hold.secret_epoch > secret_epoch);
            released = list.len() != before;
            if list.is_empty() {
                lot.remove(group_key);
            }
        }
    }
    {
        let mut marks = state
            .gss_share_holds
            .keyless
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if marks
            .get(group_key)
            .is_some_and(|mark| mark.secret_epoch <= secret_epoch)
        {
            released |= marks.remove(group_key).is_some();
        }
    }
    if released {
        persist_logged(state, group_key).await;
    }
}

/// #1663: the own-seat key republication ends the keyless survivor's
/// holds. A node that holds no group secret can not seal anything under a
/// stale secret — the no-secret refusal answers its sends until the
/// re-sealed share installs — so the withholding reason is gone once the
/// seat can take a share again. Two scopes keep the S4 invariants: a node
/// that still holds a secret keeps every hold (the old secret must never
/// be reused; only the share installs ends its wait), and a hold that
/// still carries `removed` evidence (the #1533 share-actor gates) keeps
/// waiting for its ordinary end. See [`republish_releases`].
pub(super) async fn release_keyless_on_republish(
    state: &AppState,
    group_key: &str,
    info: &x0x::groups::GroupInfo,
) {
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
        list.retain(|hold| !republish_releases(info, hold));
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

/// Whether the #1663 key republication ends this hold on a node whose
/// group state is `info`: yes only when the hold is live, the node holds
/// no secret and the hold carries no removal evidence; no when the node
/// still holds a secret (the old secret must never be reused) or the
/// hold still gates share actors. A dead hold waits for the ordinary
/// [`prune_exclusions`], which a share install runs.
fn republish_releases(info: &x0x::groups::GroupInfo, hold: &ExclusionHold) -> bool {
    holds(info, Some(hold.secret_epoch)) && info.shared_secret.is_none() && hold.removed.is_empty()
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
            .gss_share_holds
            .share_senders
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for alias in aliases.clone() {
            lot.remove(alias);
        }
    }
    {
        let mut lot = state
            .gss_share_holds
            .keyless
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
        if crate::w3h_inline::fs::remove_file(&path).await.is_ok() {
            let _ = super::sync_parent_dir_for_path(&path);
        }
    }
}

#[cfg(test)]
pub(in crate::server) mod test_seam {
    use super::*;

    /// A restart: memory loses every parked removal, held exclusion, share
    /// sender and keyless mark (#1766, #1775), and the next check loads
    /// the files again.
    pub(in crate::server) async fn simulate_restart(state: &AppState) {
        state
            .parked_gss_removals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        state
            .gss_share_holds
            .share_senders
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        state
            .gss_share_holds
            .keyless
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A GSS group whose retained head commit binds `epoch` — the state a
    /// survivor keeps while a sealed share raises its local epoch above
    /// the head's (#1775 item 2). `committed_secret_epoch` reads the
    /// retained head, so without the commit the local epoch would fall
    /// back as committed.
    fn gss_info_at_head(epoch: u64, secret: Option<[u8; 32]>) -> x0x::groups::GroupInfo {
        let mut info = x0x::groups::GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            crate::identity::AgentId([1u8; 32]),
            "ab".repeat(16),
        );
        info.secret_epoch = epoch;
        info.shared_secret = secret.map(|secret| secret.to_vec());
        let binding = format!("gss:epoch={epoch}");
        info.security_binding = Some(binding.clone());
        info.commit_log
            .push(x0x::groups::state_commit::RetainedCommit {
                commit: x0x::groups::state_commit::GroupStateCommit {
                    group_id: info.stable_group_id().to_string(),
                    revision: 1,
                    prev_state_hash: None,
                    roster_root: String::new(),
                    policy_hash: String::new(),
                    public_meta_hash: String::new(),
                    security_binding: Some(binding),
                    state_hash: info.state_hash.clone(),
                    withdrawn: false,
                    committed_by: String::new(),
                    committed_at: 0,
                    signer_public_key: String::new(),
                    signature: String::new(),
                },
                roster: std::collections::BTreeMap::new(),
                meta: None,
            });
        info
    }

    /// A parked `MemberRemoved` of `epoch`, sent by `sender`.
    fn parked_removal(sender: [u8; 32], epoch: u64) -> ParkedRoleUpdate {
        ParkedRoleUpdate {
            event: NamedGroupMetadataEvent::MemberRemoved {
                group_id: "g".to_string(),
                revision: 2,
                actor: "01".repeat(32),
                agent_id: "02".repeat(32),
                treekem_commit_b64: None,
                treekem_epoch: None,
                secret_epoch: Some(epoch),
                commit: None,
            },
            sender: crate::identity::AgentId(sender),
            parked_at: Instant::now(),
        }
    }

    async fn test_state() -> (std::sync::Arc<AppState>, tempfile::TempDir) {
        super::super::tests::secure_endpoint_test_state()
            .await
            .expect("the test state builds")
    }

    /// #1775 item 4: a #1578 keyless commit binds its epoch with no
    /// secret, so it pins no secret value. The durable mark keeps the
    /// group's ciphertext held under the first foreign share of that
    /// epoch, keeps that share's sender recorded, and lets the waiting
    /// actor's own share replace it; the settled epoch is pinned again,
    /// and a restart keeps the mark.
    #[tokio::test]
    async fn a_keyless_commit_pins_no_secret_value() {
        let (state, _dir) = test_state().await;
        let group_key = "g".to_string();
        let actor = "aa".repeat(32);
        let other = "bb".repeat(32);
        let keyless = gss_info_at_head(2, None);
        note_keyless_commit(&state, &group_key, 2, &actor).await;
        // The frame's retry re-parks its hold on the keyless commit too;
        // the mark keeps that hold live under a foreign secret as well.
        hold_exclusion(&state, &group_key, "p", 2, &actor).await;
        let foreign = [0xB5u8; 32];
        let mut info = keyless.clone();
        info.shared_secret = Some(foreign.to_vec());
        note_share_sender(&state, &group_key, &keyless, 2, &other, &foreign).await;
        assert!(
            withholds(&state, &group_key, &info),
            "#1775 item 4: the keyless commit's mark keeps holding under the first foreign share"
        );
        assert!(
            replaces_uncommitted_secret(&state, &group_key, &info, &actor, 2),
            "the waiting actor's share may replace the foreign secret"
        );
        // The mark is durable: a restart that loads the files keeps it.
        super::test_seam::simulate_restart(&state).await;
        ensure_loaded(&state).await;
        assert!(
            withholds(&state, &group_key, &info),
            "the mark survives the restart"
        );
        // The actor's share installs — sealed by a sender whose hex the
        // record compares case-insensitively — the mark settles, and the
        // epoch is pinned again.
        let own = [0x07u8; 32];
        info.shared_secret = Some(own.to_vec());
        note_share_sender(&state, &group_key, &keyless, 2, &actor.to_uppercase(), &own).await;
        assert!(
            !withholds(&state, &group_key, &info),
            "the actor's own key ends the wait"
        );
        assert!(
            !replaces_uncommitted_secret(&state, &group_key, &info, &other, 2),
            "the settled epoch is pinned: no later share replaces it"
        );
        // A head that commits a later epoch ends the mark of this one
        // (and writes the file away).
        note_keyless_commit(&state, &group_key, 2, &actor).await;
        let later = gss_info_at_head(3, Some(foreign));
        assert!(
            !withholds(&state, &group_key, &later),
            "the mark holds only its own epoch"
        );
        assert!(prune_exclusions(&state, &group_key, &later));
        persist(&state, &group_key).await.expect("write the holds");
        assert!(
            !super::test_seam::hold_file_exists(&state, &group_key),
            "a head that commits a later epoch prunes the stale mark"
        );
    }

    /// #1775 item 1, the parked-list and replace halves: a parked removal
    /// keeps holding under an installed secret that no commit pins, unless
    /// the removal's own sender sealed it. The removal's sender's share
    /// still replaces a foreign secret of the waiting epoch; a committed
    /// secret ends the wait.
    #[tokio::test]
    async fn a_parked_removal_waits_under_an_unpinned_foreign_secret() {
        let (state, _dir) = test_state().await;
        let group_key = "g".to_string();
        let remover = "11".repeat(32);
        let other = "bb".repeat(32);
        let parent = gss_info_at_head(1, Some([0x99u8; 32]));
        state
            .parked_gss_removals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(group_key.clone())
            .or_default()
            .push(parked_removal([0x11; 32], 2));
        let foreign = [0xB5u8; 32];
        let mut info = parent.clone();
        info.secret_epoch = 2;
        info.shared_secret = Some(foreign.to_vec());
        note_share_sender(&state, &group_key, &parent, 2, &other, &foreign).await;
        assert!(
            withholds(&state, &group_key, &info),
            "#1775 item 1: a parked removal keeps holding under an unpinned foreign secret"
        );
        assert!(
            replaces_uncommitted_secret(&state, &group_key, &info, &remover, 2),
            "the removal's sender may replace the foreign secret"
        );
        let settled = gss_info_at_head(2, Some(foreign));
        assert!(
            !withholds(&state, &group_key, &settled),
            "a committed secret of the epoch ends the wait"
        );
        let own = [0x07u8; 32];
        let mut own_info = parent.clone();
        own_info.secret_epoch = 2;
        own_info.shared_secret = Some(own.to_vec());
        note_share_sender(&state, &group_key, &parent, 2, &remover, &own).await;
        assert!(
            !withholds(&state, &group_key, &own_info),
            "the removal's own sender's secret ends the wait"
        );
        assert!(
            !replaces_uncommitted_secret(&state, &group_key, &own_info, &other, 2),
            "once the removal's sender's secret is in, no other share replaces it"
        );
    }

    /// #1775 item 3: a hold file that pre-#1771 code wrote carries no
    /// actor list. Its actors are unknown, so no secret that no commit
    /// pins ends the hold: there is no window between the upgrade and the
    /// frame's retry, which records its actor and narrows the wait.
    #[tokio::test]
    async fn a_pre_upgrade_hold_file_waits_fail_closed() {
        let (state, _dir) = test_state().await;
        let group_key = "g".to_string();
        let actor = "aa".repeat(32);
        let other = "bb".repeat(32);
        let pre_upgrade = "{\"version\":1,\"group_key\":\"g\",\"exclusions\":\
             [{\"parent_state_hash\":\"p\",\"secret_epoch\":2}]}"
            .to_string();
        let path = super::test_seam::hold_path_for(&state, &group_key);
        std::fs::create_dir_all(path.parent().expect("the hold dir has a parent"))
            .expect("make the hold dir");
        std::fs::write(&path, pre_upgrade).expect("write the pre-#1771 hold file");
        let parent = gss_info_at_head(1, None);
        let foreign = [0xB5u8; 32];
        let mut info = parent.clone();
        info.secret_epoch = 2;
        info.shared_secret = Some(foreign.to_vec());
        note_share_sender(&state, &group_key, &parent, 2, &other, &foreign).await;
        assert!(
            withholds(&state, &group_key, &info),
            "#1775 item 3: an actorless pre-upgrade hold is not ended by an unpinned secret"
        );
        // The frame retries and records its actor: from then on only its
        // own key ends the wait.
        hold_exclusion(&state, &group_key, "p", 2, &actor).await;
        assert!(
            withholds(&state, &group_key, &info),
            "the foreign secret still holds the retrying exclusion's wait"
        );
        let own = [0x07u8; 32];
        let mut own_info = parent.clone();
        own_info.secret_epoch = 2;
        own_info.shared_secret = Some(own.to_vec());
        note_share_sender(&state, &group_key, &parent, 2, &actor, &own).await;
        assert!(
            !withholds(&state, &group_key, &own_info),
            "the recorded actor's own key ends the wait"
        );
    }

    /// #1775 item 3 (claude review round 1): a pre-#1771 evicted-removal
    /// hold carries removed members and no actor list, and #1771 wrote
    /// known-empty actor lists the same way. Such a hold is actorless by
    /// design, not unknown: it keeps the old rule, so it does not wait
    /// for a frame retry that an evicted removal no longer has.
    #[tokio::test]
    async fn a_pre_upgrade_evicted_removal_hold_keeps_the_old_rule() {
        let (state, _dir) = test_state().await;
        let group_key = "g".to_string();
        let other = "bb".repeat(32);
        let file = "{\"version\":1,\"group_key\":\"g\",\"exclusions\":\
             [{\"parent_state_hash\":\"p\",\"secret_epoch\":2,\
             \"removed\":[\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"]}]}"
            .to_string();
        let path = super::test_seam::hold_path_for(&state, &group_key);
        std::fs::create_dir_all(path.parent().expect("the hold dir has a parent"))
            .expect("make the hold dir");
        std::fs::write(&path, file).expect("write the pre-#1771 evicted-removal hold file");
        let parent = gss_info_at_head(1, None);
        let foreign = [0xB5u8; 32];
        let mut info = parent.clone();
        info.secret_epoch = 2;
        info.shared_secret = Some(foreign.to_vec());
        note_share_sender(&state, &group_key, &parent, 2, &other, &foreign).await;
        assert!(
            !withholds(&state, &group_key, &info),
            "the old rule: an actorless containment ends at any secret of its epoch, committed or not"
        );
        let settled = gss_info_at_head(2, Some(foreign));
        assert!(
            !withholds(&state, &group_key, &settled),
            "an evicted removal's hold ends at a committed secret of its epoch"
        );
    }

    /// #1775, the load-side merge: a hold file that two exclusions of one
    /// parent and epoch wrote keeps both actors across a restart. On main
    /// the second entry's actor was dropped, so that actor's own
    /// uncommitted secret kept holding its group's ciphertext for ever.
    #[tokio::test]
    async fn the_load_merge_keeps_every_actor() {
        let (state, _dir) = test_state().await;
        let group_key = "g".to_string();
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let file = format!(
            "{{\"version\":1,\"group_key\":\"g\",\"exclusions\":\
             [{{\"parent_state_hash\":\"p\",\"secret_epoch\":2,\"actors\":[\"{first}\"]}},\
             {{\"parent_state_hash\":\"p\",\"secret_epoch\":2,\"actors\":[\"{second}\"]}}]}}"
        );
        let path = super::test_seam::hold_path_for(&state, &group_key);
        std::fs::create_dir_all(path.parent().expect("the hold dir has a parent"))
            .expect("make the hold dir");
        std::fs::write(&path, file).expect("write the hold file");
        let parent = gss_info_at_head(1, None);
        let second_secret = [0xB5u8; 32];
        let mut info = parent.clone();
        info.secret_epoch = 2;
        info.shared_secret = Some(second_secret.to_vec());
        note_share_sender(&state, &group_key, &parent, 2, &second, &second_secret).await;
        assert!(
            !withholds(&state, &group_key, &info),
            "the second actor's own uncommitted key ends its merged wait"
        );
    }

    /// #1775: the cap eviction does not move the dropped hold's waiting
    /// actors to a later epoch's hold — an actor of the dropped epoch may
    /// not end a later epoch's wait (that would fail open). Its exclusion
    /// frame retries and re-parks its hold, so its actor check returns.
    /// The probe reads the surviving epoch-2 hold directly: the holds
    /// above the probe epoch would keep `withholds` true whatever the
    /// merge did.
    #[tokio::test]
    async fn the_cap_eviction_moves_no_actor_to_a_later_epoch() {
        let (state, _dir) = test_state().await;
        let group_key = "g".to_string();
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        for epoch in 1..=(super::super::PARKED_ROLE_UPDATE_CAP as u64 + 1) {
            hold_exclusion(&state, &group_key, "p", epoch, &first).await;
        }
        hold_exclusion(&state, &group_key, "q", 2, &second).await;
        let parent = gss_info_at_head(1, None);
        let first_secret = [0xB5u8; 32];
        let mut info = parent.clone();
        info.secret_epoch = 2;
        info.shared_secret = Some(first_secret.to_vec());
        note_share_sender(&state, &group_key, &parent, 2, &first, &first_secret).await;
        let held = state
            .gss_share_holds
            .exclusions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&group_key)
            .cloned()
            .expect("the group's holds");
        let at_two = held
            .iter()
            .find(|hold| hold.secret_epoch == 2)
            .expect("the epoch-2 hold survived the cap");
        assert!(
            hold_live(&state, &group_key, &info, at_two, Some(&first)),
            "the dropped epoch's actor does not end the later epoch's wait"
        );
    }

    /// #1775, the smaller items: a same-parent-and-epoch merge keeps every
    /// actor once, case-insensitively, and an unknown actor list (a
    /// pre-#1771 file) stays unknown on load.
    #[test]
    fn actor_merges_keep_every_waiter() {
        let mut known = Some(vec!["aa".repeat(32)]);
        merge_actors(&mut known, Some(vec!["AA".repeat(32)]));
        assert_eq!(
            known.as_ref().map(Vec::len),
            Some(1),
            "the merge is case-insensitive"
        );
        merge_actors(&mut known, Some(vec!["cc".repeat(32)]));
        assert_eq!(known.as_ref().map(Vec::len), Some(2));
        merge_actors(&mut known, None);
        assert!(known.is_none(), "an unknown list dominates a merge on load");
    }

    /// #1663: the key republication ends exactly the keyless survivor's
    /// holds. A node that holds no secret and no removal evidence drops
    /// the hold (it can not seal anything under a stale secret — the
    /// no-secret refusal answers its sends until the share installs); a
    /// node that still holds the old secret keeps every hold (the old
    /// secret must never be reused), and a hold that still gates share
    /// actors keeps waiting for its ordinary end.
    #[test]
    fn the_key_republication_ends_only_the_secretless_evidence_free_holds() {
        let mut keyless = x0x::groups::GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            crate::identity::AgentId([1u8; 32]),
            "ab".repeat(16),
        );
        keyless.secret_epoch = 2;
        keyless.shared_secret = None;
        let live = ExclusionHold {
            parent_state_hash: "parent".to_string(),
            secret_epoch: 2,
            removed: Vec::new(),
            actors: Some(Vec::new()),
        };
        assert!(
            republish_releases(&keyless, &live),
            "the keyless install's hold ends with the republication"
        );
        let with_evidence = ExclusionHold {
            removed: vec!["aa".repeat(32)],
            ..live.clone()
        };
        assert!(
            !republish_releases(&keyless, &with_evidence),
            "a hold that still gates share actors keeps waiting"
        );
        keyless.shared_secret = Some(vec![7u8; 32]);
        assert!(
            !republish_releases(&keyless, &live),
            "a node that still holds a secret keeps withholding it"
        );
        keyless.shared_secret = None;
        keyless.secret_epoch = 3;
        assert!(
            !republish_releases(&keyless, &live),
            "a dead hold waits for the ordinary prune"
        );
    }

    /// #1578 rc3 (review finding 1): the keyless claim is derived from
    /// the group state, not from the hold file. A hold write that fails
    /// and the restart after it leave the keyless install with no hold
    /// anywhere — the claim stays absent. Before the fix the saved head
    /// was served as soon as no hold named the epoch, and the node
    /// claimed a head it holds no key for.
    #[test]
    fn a_keyless_install_claims_no_head_with_no_hold_anywhere() {
        assert_eq!(
            reported_head(true, true, "keyless-result-head", false, true),
            None
        );
    }

    /// #1578 rc4 (Engineer ruling, 28 Oct 09:35 GMT; Claude blocking 1,
    /// Codex P2 on #1635): a SignedPublic group is GSS-plane by default
    /// and holds no secret and no seat KEM key by design, so its members
    /// are not keyless survivors. Every invite-joined SignedPublic
    /// member matched the rc3 predicate and disclaimed its head for
    /// ever, with no survivor-convergence evidence left for its S4
    /// removal, rebind and owner-recovery rows. The confidentiality
    /// check keeps main's answer.
    #[test]
    fn a_signed_public_member_claims_its_saved_head() {
        assert_eq!(
            reported_head(true, false, "saved-head", false, true),
            Some("saved-head".to_string())
        );
    }

    /// #1578 rc3 (rc3 review, plane gate): a member of any other plane
    /// — a TreeKEM joiner, which holds heads with no GSS secret and no
    /// seat KEM key by design — keeps main's answer. Without the plane
    /// gate every such joiner would disclaim its head for ever.
    #[test]
    fn a_non_gss_member_claims_its_saved_head() {
        assert_eq!(
            reported_head(false, true, "saved-head", false, true),
            Some("saved-head".to_string())
        );
    }

    /// #1578 rc3 (David's ruling, 28 Oct 02:09 GMT): a superseded
    /// intermediate install keeps its hold at the epoch and holds no
    /// secret, but its own seat carries a KEM key, so it is not keyless:
    /// it claims its saved head, exactly as on main. Before the fix the
    /// hold at the epoch made the claim absent.
    #[test]
    fn a_superseded_intermediate_install_claims_its_saved_head() {
        assert_eq!(
            reported_head(true, true, "saved-head", false, false),
            Some("saved-head".to_string())
        );
    }

    /// #1578: a node whose own seat is keyless but that holds the
    /// secret (the exclusion's author on a snapshot-derived roster,
    /// which strips every KEM key) vouches for the head it sealed: it
    /// claims its saved head.
    #[test]
    fn a_keyless_seat_that_holds_the_secret_claims_its_saved_head() {
        assert_eq!(
            reported_head(true, true, "saved-head", true, true),
            Some("saved-head".to_string())
        );
    }

    /// With a secret and a keyed seat the node claims its saved head.
    #[test]
    fn a_keyed_node_claims_its_saved_head() {
        assert_eq!(
            reported_head(true, true, "saved-head", true, false),
            Some("saved-head".to_string())
        );
    }
}
