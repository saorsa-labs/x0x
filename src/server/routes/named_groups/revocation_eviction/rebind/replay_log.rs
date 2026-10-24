//! ADR 0110 §4a and §4b(1) restart durability (#1508 review): the held
//! log of the certificate-rebind and owner-recovery frames, and of the
//! received `CryptoExclusionV1` frames (§4, #1508 review Codex P1).
//!
//! A survivor that missed a rebind or a recovery commit can get it only
//! from a node that holds the exact signed frame: ordinary catch-up cannot
//! rebuild it. The author held its frame in memory only, so a crash after
//! the local commit and before the delivery lost the chain link. Now the
//! author writes the group's held log with the new frame before the local
//! commit ([`write_planned`]), and a restart loads it ([`ensure_restored`]).
//! A receiver does the same before it installs a frame
//! ([`write_received`]), so a restarted receiver serves the frame to a
//! survivor that missed it while the author is offline (#1508 review F2).
//!
//! - **File.** `<data_dir>/treekem/<stem>.crblog` (rebind),
//!   `<stem>.orclog` (owner recovery) or `<stem>.celog` (crypto-only
//!   exclusion), with the `.evjournal` stem rule.
//!   It is local state, not a wire format: the header `X0XRPL1\0`, the
//!   postcard [`ReplayLogV1`], then the BLAKE3 hash of that body. The
//!   frames are the bytes that go on the wire, unchanged.
//! - **Write.** Temp write, fsync, atomic rename and directory fsync, as
//!   for the `.evjournal`. If the write fails, the commit does not occur.
//!   A file with a newer layout is never rewritten, so the commit does not
//!   occur either (fail closed). Writes of one group's log serialize (one
//!   writer at a time per file, #1579 fix round), and each starts from the
//!   frames the file already holds, then memory's, then the new frame: a
//!   restart may have left frames in the file that memory has not
//!   installed, and no write displaces what the last write made durable.
//!   In the rebind and owner-recovery logs a frame at a revision the file
//!   already holds, with a different result head, is a competing commit:
//!   both are kept, and the held frame is never replaced — the pair is the
//!   fork evidence that two commits claimed one revision (#1579). The
//!   crypto-only exclusion log keeps the #1508 rule — a received frame
//!   never replaces a held one, so one frame per revision — because its
//!   catch-up round stops at the first frame the head rule refuses: a
//!   competing pair would strand every frame after it.
//! - **Load.** A damaged file is quarantined (ADR 0108 §5a: pending name,
//!   then history name), and that group starts with an empty log: its
//!   frames are lost, the load never panics and never uses the damaged
//!   bytes. A newer layout stays on disk, not loaded. A frame that is not
//!   on this node's loaded chain is not held (a crash between the write and
//!   the commit). In the rebind and owner-recovery logs, of a competing
//!   pair at the head revision the chain's frame is held; the other stays
//!   in the file as evidence and is never served (#1579). An authored
//!   frame that is still the group's head gets its delivery again. A
//!   received frame above the loaded head (a crash between the write and
//!   the install) is received again: the caller puts it through the full
//!   receive checks.
//! - **Retire.** The file holds what the writes kept — memory's frames
//!   and the frames only the file had — under the same bound, so a frame
//!   leaves the file only when that bound drops it.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};

use crate::groups::eviction::SidecarDecodeError;
use crate::groups::GroupInfo;
use crate::server::state::AppState;

use super::super::{host_commit_gate_open, S4Inner};

/// Extension of the certificate-rebind log.
pub(in super::super) const REBIND_EXTENSION: &str = "crblog";
/// Extension of the owner-recovery log.
pub(in super::super) const RECOVERY_EXTENSION: &str = "orclog";
/// Extension of the crypto-only exclusion log. It holds the received
/// frames; an authored frame is durable in its `.evs` row.
pub(in super::super) const CE_EXTENSION: &str = "celog";

const PREFIX: &[u8] = b"X0XRPL";
const HEADER_V1: &[u8; 8] = b"X0XRPL1\0";
const MAX_SUPPORTED_VERSION: u8 = 1;
const HASH_LEN: usize = 32;

/// One held frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in super::super) struct ReplayFrameV1 {
    /// The roster revision the frame produces.
    pub next_revision: u64,
    /// The head the frame produces: it is served only while this head is
    /// on the verified chain.
    pub result_head: String,
    /// This node authored the frame.
    pub authored: bool,
    /// The exact frame bytes, as sent.
    pub frame: Vec<u8>,
}

/// The v1 file: the held log of one group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in super::super) struct ReplayLogV1 {
    /// Stable group ID.
    pub stable_group_id: String,
    /// The held frames, oldest revision first.
    pub frames: Vec<ReplayFrameV1>,
}

/// What a restart loaded for the caller to act on.
#[derive(Default)]
pub(in super::super) struct Restored {
    /// Authored frames that are still their group's head: deliver again.
    pub resumes: Vec<Resume>,
    /// Received frames above their group's loaded head, durable before a
    /// crash stopped the install: receive again.
    pub received: Vec<Arc<Vec<u8>>>,
}

/// An authored frame that is its group's head after a restart: the
/// caller delivers it again.
pub(in super::super) struct Resume {
    pub stable_group_id: String,
    pub info: GroupInfo,
    pub next_revision: u64,
    pub result_head: String,
    pub bytes: Arc<Vec<u8>>,
}

/// The frames held per group for catch-up serving, at most `CAP` per
/// group, by revision, deduplicated. `KEEP_COMPETING` is the #1579 rule
/// of the rebind and owner-recovery logs; without it the #1508 rule
/// holds — one frame per revision — as for the crypto-only exclusion log.
#[derive(Debug, Default)]
pub(in super::super) struct HeldLog<const CAP: usize, const KEEP_COMPETING: bool = false> {
    log: HashMap<String, VecDeque<HeldFrame>>,
    restored: bool,
}

#[derive(Debug, Clone)]
struct HeldFrame {
    next_revision: u64,
    result_head: String,
    authored: bool,
    bytes: Arc<Vec<u8>>,
}

impl<const CAP: usize, const KEEP_COMPETING: bool> HeldLog<CAP, KEEP_COMPETING> {
    /// Keep a frame. With `KEEP_COMPETING` (the rebind and owner-recovery
    /// logs, #1579) a frame of the same commit (the revision and the
    /// result head) replaces the held copy, so one commit is held once —
    /// an authored copy replaces a received one — while a frame at a held
    /// revision with a different result head is a competing commit: both
    /// are kept and neither replaces the other. The bytes are the fork
    /// evidence that two commits claimed one revision.
    ///
    /// Without it (the crypto-only exclusion log, #1508) the frame held
    /// at a revision blocks a received frame and is replaced by an
    /// authored one, so the log — memory, file and catch-up serving —
    /// holds one frame per revision. That round stops at the first frame
    /// the head rule refuses, so a competing pair in it would strand
    /// every frame after the pair; it never meets one (#1579 fix round).
    pub(in super::super) fn remember(
        &mut self,
        stable_group_id: &str,
        next_revision: u64,
        result_head: &str,
        bytes: Arc<Vec<u8>>,
        authored: bool,
    ) {
        let log = self.log.entry(stable_group_id.to_string()).or_default();
        // The held frame this one lands on: with the keep-competing rule
        // only a frame of the same commit; without it any frame at the
        // same revision.
        if let Some(at) = log.iter().position(|e| {
            e.next_revision == next_revision && (!KEEP_COMPETING || e.result_head == result_head)
        }) {
            if !KEEP_COMPETING && !authored {
                return;
            }
            log.remove(at);
        }
        let at = log
            .iter()
            .position(|e| e.next_revision > next_revision)
            .unwrap_or(log.len());
        log.insert(
            at,
            HeldFrame {
                next_revision,
                result_head: result_head.to_string(),
                authored,
                bytes,
            },
        );
        while log.len() > CAP {
            log.pop_front();
        }
    }

    /// Hold every frame of `other` too, with the [`Self::remember`] rule.
    /// This log's load state is kept: `other` is a rebuilt view that holds
    /// no file frames.
    pub(in super::super) fn absorb(&mut self, other: Self) {
        for (stable, frames) in other.log {
            for e in frames {
                self.remember(
                    &stable,
                    e.next_revision,
                    &e.result_head,
                    e.bytes,
                    e.authored,
                );
            }
        }
    }

    /// The frames held for any of `group_ids` above `from_revision`, oldest
    /// first, with their group ID and result head.
    pub(in super::super) fn catchup_frames(
        &self,
        group_ids: &[String],
        from_revision: u64,
    ) -> Vec<(String, String, Arc<Vec<u8>>)> {
        group_ids
            .iter()
            .find_map(|id| self.log.get(id).map(|log| (id, log)))
            .map(|(id, log)| {
                log.iter()
                    .filter(|e| e.next_revision > from_revision)
                    .map(|e| (id.clone(), e.result_head.clone(), Arc::clone(&e.bytes)))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(in super::super) fn len(&self, stable_group_id: &str) -> Option<usize> {
        self.log.get(stable_group_id).map(VecDeque::len)
    }

    fn file(&self, stable_group_id: &str) -> ReplayLogV1 {
        let frames = self.log.get(stable_group_id).into_iter().flatten();
        ReplayLogV1 {
            stable_group_id: stable_group_id.to_string(),
            frames: frames
                .map(|e| ReplayFrameV1 {
                    next_revision: e.next_revision,
                    result_head: e.result_head.clone(),
                    authored: e.authored,
                    frame: e.bytes.to_vec(),
                })
                .collect(),
        }
    }

    /// The file of the group after it also holds the frame: the frames the
    /// file holds, then memory's, then the new frame, each under the
    /// [`Self::remember`] rule. The file can hold frames memory does not
    /// (a crash between a write and its commit or install), so a new
    /// write never displaces them (#1579).
    fn planned(
        &self,
        file_frames: &[ReplayFrameV1],
        stable: &str,
        (revision, head): (u64, &str),
        bytes: &Arc<Vec<u8>>,
        authored: bool,
    ) -> ReplayLogV1 {
        let mut scratch = Self::default();
        for frame in file_frames {
            scratch.remember(
                stable,
                frame.next_revision,
                &frame.result_head,
                Arc::new(frame.frame.clone()),
                frame.authored,
            );
        }
        if let Some(log) = self.log.get(stable) {
            for e in log {
                scratch.remember(
                    stable,
                    e.next_revision,
                    &e.result_head,
                    Arc::clone(&e.bytes),
                    e.authored,
                );
            }
        }
        scratch.remember(stable, revision, head, Arc::clone(bytes), authored);
        scratch.file(stable)
    }

    /// Hold the frames of `logs` that are on `groups`' loaded chain again.
    /// Returns the authored frames that are still their group's head, and
    /// the received frames above it.
    pub(in super::super) fn restore(
        &mut self,
        logs: Vec<ReplayLogV1>,
        groups: &HashMap<String, GroupInfo>,
    ) -> Restored {
        self.restored = true;
        let mut restored = Restored::default();
        for log in logs {
            let Some(info) = groups.get(&log.stable_group_id) else {
                continue;
            };
            let stable = log.stable_group_id;
            for frame in log.frames {
                let at_head = frame.next_revision == info.state_revision
                    && frame.result_head == info.state_hash;
                if !(at_head || frame.next_revision < info.state_revision) {
                    if !frame.authored && frame.next_revision > info.state_revision {
                        restored.received.push(Arc::new(frame.frame));
                    }
                    continue;
                }
                let bytes = Arc::new(frame.frame);
                let (revision, head) = (frame.next_revision, frame.result_head);
                self.remember(&stable, revision, &head, Arc::clone(&bytes), frame.authored);
                if at_head && frame.authored {
                    restored.resumes.push(Resume {
                        stable_group_id: stable.clone(),
                        info: info.clone(),
                        next_revision: revision,
                        result_head: head,
                        bytes,
                    });
                }
            }
        }
        restored
    }
}

/// Encode one file.
fn encode(log: &ReplayLogV1) -> Result<Vec<u8>, postcard::Error> {
    encode_local_file(HEADER_V1, log)
}

/// Decode one file, with the ADR 0108 §5a classification of a file that
/// cannot be used.
fn decode(bytes: &[u8]) -> Result<ReplayLogV1, SidecarDecodeError> {
    decode_local_file(PREFIX, MAX_SUPPORTED_VERSION, bytes)
}

/// The S4 local-file layout, shared by the held frame logs and the kept
/// expiry hand-offs: the 8-byte `header` (`prefix`, version digit, NUL),
/// the postcard `body`, then the BLAKE3 hash of that body.
pub(in super::super) fn encode_local_file<T: Serialize>(
    header: &[u8; 8],
    body: &T,
) -> Result<Vec<u8>, postcard::Error> {
    let body = postcard::to_stdvec(body)?;
    let mut out = header.to_vec();
    out.extend_from_slice(&body);
    out.extend_from_slice(blake3::hash(&body).as_bytes());
    Ok(out)
}

/// Decode one [`encode_local_file`] file. A version above `max_version`
/// is [`SidecarDecodeError::NewerFormat`]; any other fault is
/// [`SidecarDecodeError::Damaged`].
pub(in super::super) fn decode_local_file<T: serde::de::DeserializeOwned>(
    prefix: &[u8],
    max_version: u8,
    bytes: &[u8],
) -> Result<T, SidecarDecodeError> {
    let rest = bytes
        .strip_prefix(prefix)
        .ok_or(SidecarDecodeError::Damaged("missing_prefix"))?;
    let (Some(&version_byte), Some(&terminator)) = (rest.first(), rest.get(1)) else {
        return Err(SidecarDecodeError::Damaged("truncated_header"));
    };
    if !(b'1'..=b'9').contains(&version_byte) || terminator != 0 {
        return Err(SidecarDecodeError::Damaged("bad_header"));
    }
    if version_byte - b'0' > max_version {
        return Err(SidecarDecodeError::NewerFormat(version_byte - b'0'));
    }
    let payload = rest.get(2..).unwrap_or_default();
    let split = payload
        .len()
        .checked_sub(HASH_LEN)
        .ok_or(SidecarDecodeError::Damaged("truncated_body"))?;
    let (body, hash) = payload.split_at(split);
    if blake3::hash(body).as_bytes().as_slice() != hash {
        return Err(SidecarDecodeError::Damaged("hash_mismatch"));
    }
    match postcard::take_from_bytes::<T>(body) {
        Ok((log, [])) => Ok(log),
        _ => Err(SidecarDecodeError::Damaged("body_decode")),
    }
}

fn log_path(state: &AppState, stable_group_id: &str, extension: &str) -> PathBuf {
    super::super::evjournal_path(state, stable_group_id).with_extension(extension)
}

/// One writer at a time per log file path (#1579 fix round): the writes of
/// one group's log serialize, so each write plans from the bytes the last
/// write left. Keyed by the full path, so distinct data directories never
/// share a lock.
static FILE_WRITE_LOCKS: LazyLock<
    tokio::sync::Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>,
> = LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

async fn lock_file_writes(path: &Path) -> Arc<tokio::sync::Mutex<()>> {
    FILE_WRITE_LOCKS
        .lock()
        .await
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Write `log` durably at `path`. A file with a newer layout is never
/// rewritten. Returns whether `log` is durable.
async fn write_at(path: &Path, log: &ReplayLogV1) -> bool {
    if let Ok(existing) = tokio::fs::read(path).await {
        if let Err(SidecarDecodeError::NewerFormat(version)) = decode(&existing) {
            tracing::warn!(version, path = %path.display(), "ADR 0110 S4: held frame log has a newer layout; the commit does not occur");
            return false;
        }
    }
    let Ok(bytes) = encode(log) else {
        return false;
    };
    match super::super::write_bytes_durably(path, &bytes, None).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "ADR 0110 S4: held frame log write failed");
            false
        }
    }
}

/// Read every file with `extension` in `dir`. A damaged file is
/// quarantined and skipped; a newer layout is skipped and kept. Inside an
/// ADR 0094 trial (`gate_open` false) a damaged file is skipped and left
/// in place (§5). The load runs once per process, so that file is not
/// quarantined later: the first write of its group's log after host
/// commit replaces it, and its frames are lost as in the quarantine case.
async fn read_all_in(dir: &Path, extension: &str, gate_open: bool) -> Vec<ReplayLogV1> {
    let mut logs = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return logs;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(extension) {
            continue;
        }
        let Ok(bytes) = tokio::fs::read(&path).await else {
            continue;
        };
        match decode(&bytes) {
            Ok(log) => logs.push(log),
            Err(SidecarDecodeError::NewerFormat(version)) => {
                tracing::warn!(version, path = %path.display(), "ADR 0110 S4: held frame log has a newer layout; not loaded");
            }
            // An ADR 0094 trial starts no quarantine (§5).
            Err(SidecarDecodeError::Damaged(reason)) if !gate_open => {
                tracing::warn!(reason, path = %path.display(), "ADR 0110 S4: damaged held frame log inside an ADR 0094 trial; not loaded and not quarantined");
            }
            Err(SidecarDecodeError::Damaged(reason)) => {
                tracing::warn!(reason, path = %path.display(), "ADR 0110 S4: damaged held frame log; quarantining (ADR 0108 §5a); its frames are lost");
                match super::super::quarantine_file(&path, &bytes).await {
                    Ok((_, pending)) => {
                        super::super::finalize_quarantine(&pending).await;
                    }
                    Err(step) => {
                        tracing::warn!(step, path = %path.display(), "ADR 0110 S4: held frame log quarantine failed");
                    }
                }
            }
        }
    }
    logs
}

/// Before the local commit: write the group's log with the authored frame
/// durably. On `false` the caller must not commit.
pub(in super::super) async fn write_planned<const CAP: usize, const KEEP: bool>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP, KEEP>,
    stable: &str,
    at: (u64, &str),
    bytes: &Arc<Vec<u8>>,
) -> bool {
    write_with(state, extension, held, stable, at, bytes, true).await
}

/// Before a received frame's state is installed: write the group's log
/// with the received frame durably, in the same file and layout as an
/// authored frame (#1508 review F2). On `false` the caller must not
/// install. If the install then fails for a local fault, the frame stays
/// in the file; the next receipt or the restart receives it again.
pub(in super::super) async fn write_received<const CAP: usize, const KEEP: bool>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP, KEEP>,
    stable: &str,
    at: (u64, &str),
    bytes: &Arc<Vec<u8>>,
) -> bool {
    write_with(state, extension, held, stable, at, bytes, false).await
}

async fn write_with<const CAP: usize, const KEEP: bool>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP, KEEP>,
    stable: &str,
    at: (u64, &str),
    bytes: &Arc<Vec<u8>>,
    authored: bool,
) -> bool {
    // §5: no S4 file write inside an ADR 0094 trial, so no commit or
    // install of this kind occurs before host commit.
    if !host_commit_gate_open(state) {
        return false;
    }
    let path = log_path(state, stable, extension);
    // #1579 fix round: one writer at a time per log file. Two writes of
    // one group at once planned from the same file bytes, and the second
    // rename dropped the first write's frame — the only durable copy in a
    // crash window. Under the per-file lock the second write reads and
    // plans from the file the first write left.
    let write_lock = lock_file_writes(&path).await;
    let _serialized = write_lock.lock().await;
    // #1579: the file may hold frames memory does not (a crash between a
    // write and its commit or install). A frame that cannot be decoded is
    // not merged; a newer layout still fails the write below (fail
    // closed), and a damaged file is replaced by this write, as by the
    // first write after the quarantine.
    let file_frames = match tokio::fs::read(&path).await {
        Ok(existing) => decode(&existing).map(|log| log.frames).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let planned = held(&mut *state.revocation_evictions.inner.lock().await).planned(
        &file_frames,
        stable,
        at,
        bytes,
        authored,
    );
    write_at(&path, &planned).await
}

/// After a failed local commit: write the group's log as memory holds it,
/// so the file does not keep the frame. Best effort: a restart drops such
/// a frame too.
pub(in super::super) async fn rewrite_from_memory<const CAP: usize, const KEEP: bool>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP, KEEP>,
    stable: &str,
) {
    if !host_commit_gate_open(state) {
        return;
    }
    let path = log_path(state, stable, extension);
    let write_lock = lock_file_writes(&path).await;
    let _serialized = write_lock.lock().await;
    let log = held(&mut *state.revocation_evictions.inner.lock().await).file(stable);
    let _durable = write_at(&path, &log).await;
}

/// Load the files once per process, before this node serves catch-up,
/// delivers, receives or authors a frame of this kind. Returns the frames
/// to deliver or receive again (empty when another call did the load).
pub(in super::super) async fn ensure_restored<const CAP: usize, const KEEP: bool>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP, KEEP>,
) -> Restored {
    if held(&mut *state.revocation_evictions.inner.lock().await).restored {
        return Restored::default();
    }
    let gate_open = host_commit_gate_open(state);
    let logs = read_all_in(&state.treekem_dir, extension, gate_open).await;
    let groups: HashMap<String, GroupInfo> = state
        .named_groups
        .read()
        .await
        .values()
        .map(|info| (info.stable_group_id().to_string(), info.clone()))
        .collect();
    let mut inner = state.revocation_evictions.inner.lock().await;
    let log = held(&mut inner);
    if log.restored {
        return Restored::default();
    }
    log.restore(logs, &groups)
}

#[cfg(test)]
pub(in super::super) mod tests {
    use super::*;

    /// The committed after-image of a two-member group: revision 5, head
    /// `h5`, with `survivor` Active.
    pub(in super::super::super) fn committed_group(
        local: crate::identity::AgentId,
        survivor: [u8; 32],
    ) -> (String, HashMap<String, GroupInfo>) {
        let mut info = GroupInfo::new("g".to_string(), String::new(), local, "cd".repeat(16));
        info.add_member(
            hex::encode(survivor),
            crate::groups::GroupRole::Member,
            Some(hex::encode(local.as_bytes())),
            None,
        );
        info.state_revision = 5;
        info.state_hash = "h5".to_string();
        let stable = info.stable_group_id().to_string();
        (stable.clone(), HashMap::from([(stable, info)]))
    }

    /// The frames a held frame log file holds on disk now (empty when the
    /// file is missing or cannot be used).
    pub(in super::super::super) async fn file_frames_of(
        path: &std::path::Path,
    ) -> Vec<ReplayFrameV1> {
        match tokio::fs::read(path).await {
            Ok(bytes) => decode(&bytes).map(|log| log.frames).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// The §4a/§4b(1) crash point on the storage path shared by both
    /// frame kinds: the frame is written before the commit, memory is
    /// lost after it, and the restart serves the exact bytes. Returns the
    /// resumed delivery.
    pub(in super::super::super) async fn crash_and_restart<const CAP: usize>(
        extension: &str,
        stable: &str,
        groups: &HashMap<String, GroupInfo>,
        frame: &Arc<Vec<u8>>,
    ) -> Vec<Resume> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("g.{extension}"));
        let mut before = HeldLog::<CAP, true>::default();
        before.remember(stable, 4, "h4", Arc::new(vec![4]), false);
        let existing = file_frames_of(&path).await;
        assert!(
            write_at(
                &path,
                &before.planned(&existing, stable, (5, "h5"), frame, true)
            )
            .await
        );
        // The commit lands, then the process dies: `before` is lost.
        drop(before);
        let mut after = HeldLog::<CAP, true>::default();
        let resumes = after
            .restore(read_all_in(dir.path(), extension, true).await, groups)
            .resumes;
        let served = after.catchup_frames(&[stable.to_string()], 4);
        assert_eq!(served.len(), 1, "the frame is missing after the restart");
        assert_eq!(served[0].1, "h5");
        assert_eq!(served[0].2.as_slice(), frame.as_slice(), "exact bytes");
        assert_eq!(after.catchup_frames(&[stable.to_string()], 3).len(), 2);

        // A crash between the write and the commit: revision 6 never
        // landed, so a restart does not serve it.
        let existing = file_frames_of(&path).await;
        let planned = after.planned(&existing, stable, (6, "h6"), &Arc::new(vec![6]), true);
        assert!(write_at(&path, &planned).await);
        let mut again = HeldLog::<CAP, true>::default();
        let _ = again.restore(read_all_in(dir.path(), extension, true).await, groups);
        assert!(again.catchup_frames(&[stable.to_string()], 5).is_empty());
        resumes
    }

    /// The frames that the group's held log file holds on disk now (empty
    /// when the file is missing or cannot be used).
    pub(in super::super::super) async fn frames_on_disk(
        state: &AppState,
        extension: &str,
        stable: &str,
    ) -> Vec<ReplayFrameV1> {
        match tokio::fs::read(log_path(state, stable, extension)).await {
            Ok(bytes) => decode(&bytes).map(|log| log.frames).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// #1579: a frame at a held revision with a different result head is a
    /// competing commit. Both are kept — an authored frame no more
    /// replaces it than a received one — while a frame of the same commit
    /// (the revision and the head) is held once.
    #[test]
    fn a_competing_frame_at_a_held_revision_is_kept_not_substituted() {
        let mut log = HeldLog::<16, true>::default();
        log.remember("g", 5, "h5a", Arc::new(vec![1]), false);
        log.remember("g", 5, "h5b", Arc::new(vec![2]), false);
        log.remember("g", 5, "h5c", Arc::new(vec![3]), true);
        log.remember("g", 6, "h6", Arc::new(vec![6]), true);
        // The same commit replaces its held copy, and a repeat adds none.
        log.remember("g", 5, "h5a", Arc::new(vec![7]), true);
        log.remember("g", 5, "h5a", Arc::new(vec![7]), true);
        let served: Vec<(String, Vec<u8>)> = log
            .catchup_frames(&["g".to_string()], 4)
            .into_iter()
            .map(|(_, head, bytes)| (head, bytes.to_vec()))
            .collect();
        assert_eq!(
            served,
            vec![
                ("h5b".to_string(), vec![2]),
                ("h5c".to_string(), vec![3]),
                ("h5a".to_string(), vec![7]),
                ("h6".to_string(), vec![6]),
            ],
            "the held frame is never replaced; the competing ones are kept"
        );
    }

    /// #1579, the file side: the log file can hold a frame memory does not
    /// (a crash between the write and the install). A received frame at
    /// that revision — here a competing one, a different commit at the
    /// same revision — is written beside the held frame, never in its
    /// place, and the file still decodes in the v1 layout.
    #[tokio::test]
    async fn a_received_competing_frame_is_written_beside_the_held_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("g.crblog");
        let held = ReplayLogV1 {
            stable_group_id: "g".to_string(),
            frames: vec![ReplayFrameV1 {
                next_revision: 5,
                result_head: "h5a".to_string(),
                authored: false,
                frame: vec![1],
            }],
        };
        assert!(write_at(&path, &held).await);
        // The crash window: memory lost the frame before its install.
        let memory = HeldLog::<16, true>::default();
        let existing = file_frames_of(&path).await;
        let planned = memory.planned(&existing, "g", (5, "h5b"), &Arc::new(vec![2]), false);
        assert!(write_at(&path, &planned).await);
        let on_disk = file_frames_of(&path).await;
        assert_eq!(on_disk.len(), 2, "both frames are on disk");
        assert_eq!(
            (
                on_disk[0].next_revision,
                on_disk[0].result_head.as_str(),
                on_disk[0].frame.as_slice(),
                on_disk[0].authored
            ),
            (5, "h5a", &[1][..], false),
            "the held frame is never replaced"
        );
        assert_eq!(
            (
                on_disk[1].next_revision,
                on_disk[1].result_head.as_str(),
                on_disk[1].frame.as_slice()
            ),
            (5, "h5b", &[2][..]),
            "the competing frame is kept as fork evidence"
        );
        // The same commit again adds no second copy.
        let existing = file_frames_of(&path).await;
        let planned = memory.planned(&existing, "g", (5, "h5a"), &Arc::new(vec![1]), false);
        assert!(write_at(&path, &planned).await);
        assert_eq!(file_frames_of(&path).await.len(), 2);
    }

    /// #1579, the load side: of a competing pair at the head revision only
    /// the chain's frame is held (the other stays file evidence, never
    /// served), and a pair above the head — the crash before either
    /// install — is received again, both frames.
    #[tokio::test]
    async fn a_competing_pair_restores_as_one_held_frame_or_both_received() {
        let (local, survivor) = (crate::identity::AgentId([1; 32]), [2u8; 32]);
        let (stable, mut groups) = committed_group(local, survivor);
        let log_of = |frames: Vec<ReplayFrameV1>| ReplayLogV1 {
            stable_group_id: stable.clone(),
            frames,
        };
        let winner = ReplayFrameV1 {
            next_revision: 5,
            result_head: "h5".to_string(),
            authored: false,
            frame: vec![1],
        };
        let loser = ReplayFrameV1 {
            next_revision: 5,
            result_head: "h5x".to_string(),
            authored: false,
            frame: vec![2],
        };

        let mut at_head = HeldLog::<16, true>::default();
        let restored = at_head.restore(vec![log_of(vec![winner.clone(), loser.clone()])], &groups);
        assert!(
            restored.received.is_empty(),
            "the head frame is not re-received"
        );
        assert_eq!(
            at_head
                .catchup_frames(std::slice::from_ref(&stable), 4)
                .len(),
            1,
            "only the chain's frame is held at the head revision"
        );

        let info = groups.get_mut(&stable).expect("group");
        info.state_revision = 4;
        info.state_hash = "h4".to_string();
        let mut above = HeldLog::<16, true>::default();
        let restored = above.restore(vec![log_of(vec![winner, loser])], &groups);
        assert_eq!(restored.received.len(), 2, "both frames are received again");
        assert!(above.catchup_frames(&[stable], 4).is_empty());
    }

    /// #1579 fix round: the crypto-only exclusion log keeps the #1508
    /// rule — one frame per revision, in memory, in its file and after a
    /// restore — because its catch-up round stops at the first frame the
    /// head rule refuses, so a competing pair would strand every frame
    /// after the pair. The rebind and owner-recovery logs, whose rounds
    /// skip an off-chain frame, keep a competing pair instead. A received
    /// frame at a held revision is dropped; an authored frame replaces
    /// the held one.
    #[tokio::test]
    async fn the_celog_rule_holds_one_frame_per_revision() {
        // Memory: the second frame of a pair is dropped, not held beside.
        let mut log = HeldLog::<16, false>::default();
        log.remember("g", 5, "h5a", Arc::new(vec![1]), false);
        log.remember("g", 5, "h5b", Arc::new(vec![2]), false);
        let held = |log: &HeldLog<16, false>| {
            log.catchup_frames(&["g".to_string()], 4)
                .into_iter()
                .map(|(_, head, bytes)| (head, bytes.to_vec()))
                .collect::<Vec<_>>()
        };
        assert_eq!(held(&log), vec![("h5a".to_string(), vec![1])]);
        log.remember("g", 5, "h5c", Arc::new(vec![3]), true);
        assert_eq!(
            held(&log),
            vec![("h5c".to_string(), vec![3])],
            "an authored frame replaces the held one, as before"
        );

        // The file: a competing received frame is not written beside the
        // crash-window frame the file already holds.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("g.celog");
        let file = ReplayLogV1 {
            stable_group_id: "g".to_string(),
            frames: vec![ReplayFrameV1 {
                next_revision: 5,
                result_head: "h5a".to_string(),
                authored: false,
                frame: vec![1],
            }],
        };
        assert!(write_at(&path, &file).await);
        let existing = file_frames_of(&path).await;
        let planned = HeldLog::<16, false>::default().planned(
            &existing,
            "g",
            (5, "h5b"),
            &Arc::new(vec![2]),
            false,
        );
        assert!(write_at(&path, &planned).await);
        let on_disk = file_frames_of(&path).await;
        assert_eq!(on_disk.len(), 1, "the competing frame is not kept");
        assert_eq!(
            (
                on_disk[0].next_revision,
                on_disk[0].result_head.as_str(),
                on_disk[0].frame.as_slice()
            ),
            (5, "h5a", &[1][..]),
            "the held frame is never replaced"
        );

        // The load: even a pair a foreign file holds below the head —
        // this code writes no pair — restores as one held frame, so that
        // round never serves, and never stops at, a competing frame.
        let (local, survivor) = (crate::identity::AgentId([1; 32]), [2u8; 32]);
        let (stable, mut groups) = committed_group(local, survivor);
        let info = groups.get_mut(&stable).expect("group");
        info.state_revision = 6;
        info.state_hash = "h6".to_string();
        let pair = ReplayLogV1 {
            stable_group_id: stable.clone(),
            frames: vec![
                ReplayFrameV1 {
                    next_revision: 5,
                    result_head: "h5a".to_string(),
                    authored: false,
                    frame: vec![1],
                },
                ReplayFrameV1 {
                    next_revision: 5,
                    result_head: "h5b".to_string(),
                    authored: false,
                    frame: vec![2],
                },
            ],
        };
        let mut restored_log = HeldLog::<16, false>::default();
        let restored = restored_log.restore(vec![pair], &groups);
        assert!(restored.received.is_empty());
        assert_eq!(
            restored_log
                .catchup_frames(std::slice::from_ref(&stable), 4)
                .len(),
            1,
            "the second frame of the pair is not held after the restore"
        );
    }

    /// #1579 fix round: two writes of one group's log at the same time.
    /// Each write must plan from the file the last write left; before the
    /// writes serialized, both planned from the same earlier bytes and the
    /// second rename dropped the first write's frame — the only durable
    /// copy in a crash window.
    #[tokio::test]
    async fn concurrent_writes_of_one_log_keep_both_frames() {
        use crate::server::routes::named_groups as ng;
        fn rebind_held(inner: &mut S4Inner) -> &mut HeldLog<16, true> {
            &mut inner.rebind.log
        }
        let (state, _dir) = ng::tests::secure_endpoint_test_state()
            .await
            .expect("test state");
        let first_frame = Arc::new(b"one".to_vec());
        let second_frame = Arc::new(b"two".to_vec());
        let (first, second) = tokio::join!(
            write_received(
                &state,
                REBIND_EXTENSION,
                rebind_held,
                "g",
                (5, "h5"),
                &first_frame,
            ),
            write_received(
                &state,
                REBIND_EXTENSION,
                rebind_held,
                "g",
                (6, "h6"),
                &second_frame,
            ),
        );
        assert!(first && second, "both writes are durable");
        let on_disk = frames_on_disk(&state, REBIND_EXTENSION, "g").await;
        let held: Vec<(u64, &str)> = on_disk
            .iter()
            .map(|frame| (frame.next_revision, frame.result_head.as_str()))
            .collect();
        assert_eq!(
            held,
            vec![(5, "h5"), (6, "h6")],
            "a concurrent write displaces nothing the other made durable"
        );
    }

    #[test]
    fn a_held_frame_log_round_trips_and_a_flipped_byte_is_damaged() {
        let log = ReplayLogV1 {
            stable_group_id: "g".to_string(),
            frames: vec![ReplayFrameV1 {
                next_revision: 3,
                result_head: "h3".to_string(),
                authored: true,
                frame: b"frame".to_vec(),
            }],
        };
        let bytes = encode(&log).expect("encode");
        assert_eq!(decode(&bytes), Ok(log));
        for at in [0, HEADER_V1.len() + 3, bytes.len() - 1] {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0x01;
            assert!(matches!(
                decode(&damaged),
                Err(SidecarDecodeError::Damaged(_))
            ));
        }
        let truncated = decode(&bytes[..bytes.len() - 1]);
        assert_eq!(truncated, Err(SidecarDecodeError::Damaged("hash_mismatch")));
    }

    /// A damaged file fails closed: no panic, no frames, and the file is
    /// moved aside under the ADR 0108 §5a history name. A newer layout is
    /// not loaded and never rewritten, so the commit does not occur.
    #[tokio::test]
    async fn a_corrupt_held_frame_log_is_quarantined_and_a_newer_one_is_kept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let damaged = dir.path().join("aa.crblog");
        tokio::fs::write(&damaged, b"X0XRPL1\0not a log")
            .await
            .expect("write");
        assert!(read_all_in(dir.path(), REBIND_EXTENSION, true)
            .await
            .is_empty());
        assert!(!damaged.exists(), "the damaged file is moved aside");
        let mut entries = tokio::fs::read_dir(dir.path()).await.expect("read_dir");
        let entry = entries.next_entry().await.expect("entry").expect("one");
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            name.starts_with("aa.crblog.q-") && !name.ends_with(".pending"),
            "{name}"
        );

        let newer = dir.path().join("bb.crblog");
        let log = ReplayLogV1 {
            stable_group_id: "g".to_string(),
            frames: Vec::new(),
        };
        let mut bytes = encode(&log).expect("encode");
        bytes[PREFIX.len()] = b'2';
        tokio::fs::write(&newer, &bytes).await.expect("write");
        assert!(read_all_in(dir.path(), REBIND_EXTENSION, true)
            .await
            .is_empty());
        assert!(
            !write_at(&newer, &log).await,
            "a newer layout blocks the commit"
        );
        assert_eq!(tokio::fs::read(&newer).await.expect("kept"), bytes);
    }
}
