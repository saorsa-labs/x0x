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
//!   occur either (fail closed). A file that cannot be read at all fails
//!   the write the same way: only a missing file plans as empty (review).
//!   A file that cannot be decoded also plans as empty, and the write
//!   replaces it, as the first write after the quarantine does.
//!   Writes of one group's log serialize (one writer at a time per file,
//!   #1579 fix round). In the rebind and owner-recovery logs each write
//!   starts from the frames the file already holds, then memory's, then
//!   the new frame: a restart may have left frames in the file that
//!   memory has not installed, and the only frames a write drops are the
//!   ones the bound below drops. A frame at a revision the file already
//!   holds, with a different result head, is a competing commit: the
//!   pair is the fork evidence that two commits claimed one revision
//!   (#1579), and a revision holds at most two file-only frames plus the
//!   newest write's — a third file-only frame leaves with the next
//!   write, so a signer cannot fill the per-group cap at one revision
//!   and evict the catch-up window below the head. A refused commit or
//!   install removes its own frame first and no other
//!   ([`rewrite_without`]). The crypto-only exclusion log keeps the
//!   #1508 rule — a received frame never replaces a held one, so one
//!   frame per revision — and its writes plan from memory plus the new
//!   frame only, as before #1579: a stale frame only the file holds, at
//!   any revision, leaves with the next write, because the load holds it
//!   with no chain check and that log's catch-up round stops at the first
//!   frame the head rule refuses (#1579 fix round 3).
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
//! - **Retire.** In the rebind and owner-recovery logs the file holds
//!   what the writes kept — memory's frames and the frames only the file
//!   had — under the same bound, so a frame leaves the file only when
//!   that bound drops it. The crypto-only exclusion log's file holds
//!   memory's frames plus the last frame written, under the same bound.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Weak};

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
    /// result head) replaces the held copy — whichever copy arrived first,
    /// authored or received — so one commit is held once, while a frame at
    /// a held revision with a different result head is a competing commit:
    /// both are kept and neither replaces the other. The bytes are the fork
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

    /// The file of the group after it also holds the frame. With the
    /// keep-competing rule (the rebind and owner-recovery logs, #1579)
    /// the frames the file already holds come first, then memory's, then
    /// the new frame: the file can hold frames memory does not (a crash
    /// between a write and its commit or install), and that fork evidence
    /// is never displaced. Without the rule (the crypto-only exclusion
    /// log) the file is planned from memory plus the new frame only, as
    /// before #1579 (#1579 fix round 3): a stale frame only the file
    /// holds — at any revision, claimed or not — leaves with the write,
    /// because `restore` holds it with no chain check and that log's
    /// catch-up round stops at the first frame the head rule refuses,
    /// stranding every frame after it.
    fn planned(
        &self,
        file_frames: &[ReplayFrameV1],
        stable: &str,
        (revision, head): (u64, &str),
        bytes: &Arc<Vec<u8>>,
        authored: bool,
    ) -> ReplayLogV1 {
        let mut scratch = Self::default();
        if KEEP_COMPETING {
            // #1579 review: a revision keeps the competing pair and no
            // more. A signer allowed to commit can seal many distinct
            // valid frames at one revision; without the bound they fill
            // the per-group cap and `remember`'s `pop_front` evicts the
            // frames below the head — the catch-up window this log
            // serves — and eventually the held frame. Two file-only
            // frames per revision are the pair this log exists to keep
            // (before the winner installs, both are file-only); a frame
            // memory also holds is the installed chain, kept by the
            // bound. The per-group cap still trims what the merge built,
            // and the trim drops the lowest revision, memory-held or not:
            // every fork kept shrinks the window below the head.
            let mut competing: std::collections::BTreeMap<u64, u32> =
                std::collections::BTreeMap::new();
            for frame in file_frames {
                let held = self.log.get(stable).is_some_and(|log| {
                    log.iter().any(|e| {
                        e.next_revision == frame.next_revision && e.result_head == frame.result_head
                    })
                });
                if !held {
                    let seen = competing.entry(frame.next_revision).or_insert(0);
                    *seen += 1;
                    if *seen > 2 {
                        continue;
                    }
                }
                scratch.remember(
                    stable,
                    frame.next_revision,
                    &frame.result_head,
                    Arc::new(frame.frame.clone()),
                    frame.authored,
                );
            }
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

    /// The file of the group after the refused commit leaves it: the
    /// frames the file holds and memory's, minus that one commit (#1579
    /// fix round 2). A competing frame at the refused revision stays, and
    /// so does every crash-window frame memory has not installed; memory
    /// never holds the refused commit, because a frame is remembered only
    /// after its commit or install succeeds.
    fn planned_without(
        &self,
        file_frames: &[ReplayFrameV1],
        stable: &str,
        (refused_revision, refused_head): (u64, &str),
    ) -> ReplayLogV1 {
        let mut scratch = Self::default();
        // The same competing-pair bound as [`Self::planned`]: this
        // rewrite is a write of the merged view, so it must not keep a
        // per-revision pile the cap would evict the held frames for.
        // The refused frame leaves before the bound counts, so it takes
        // no place: with the file holding [A, B, C] at one revision and
        // A refused, B and C keep the two places and A is gone — not the
        // shape where A and B consume the bound and the valid C leaves
        // (review). Memory never holds the refused commit (a frame is
        // remembered only after its commit or install succeeds), so
        // skipping the file frames removes it everywhere.
        let mut competing: std::collections::BTreeMap<u64, u32> = std::collections::BTreeMap::new();
        for frame in file_frames {
            if frame.next_revision == refused_revision && frame.result_head == refused_head {
                continue;
            }
            let held = self.log.get(stable).is_some_and(|log| {
                log.iter().any(|e| {
                    e.next_revision == frame.next_revision && e.result_head == frame.result_head
                })
            });
            if !held {
                let seen = competing.entry(frame.next_revision).or_insert(0);
                *seen += 1;
                if *seen > 2 {
                    continue;
                }
            }
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
/// share a lock. The map holds weak references and drops the dead ones at
/// each insert, so a lock no write holds leaves with its entry: the map is
/// bounded by the logs being written, not by every group this process
/// ever served (#1579 fix rounds 2 and 3).
static FILE_WRITE_LOCKS: LazyLock<
    tokio::sync::Mutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>,
> = LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

async fn lock_file_writes(path: &Path) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = FILE_WRITE_LOCKS.lock().await;
    locks.retain(|_, lock| lock.upgrade().is_some());
    if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
    lock
}

/// Write `log` durably at `path`. A file with a newer layout is never
/// rewritten. Returns whether `log` is durable.
async fn write_at(path: &Path, log: &ReplayLogV1) -> bool {
    if let Ok(existing) = crate::w3h_inline::fs::read(path).await {
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
    let Ok(mut entries) = crate::w3h_inline::fs::read_dir(dir).await else {
        return logs;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(extension) {
            continue;
        }
        let bytes = match crate::w3h_inline::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %path.display(),
                    "ADR 0110 S4: held frame log could not be read at startup; not loaded"
                );
                continue;
            }
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
    // #1579: with the keep-competing rule the file may hold frames memory
    // does not (a crash between a write and its commit or install), so
    // the plan starts from them, under the per-file lock above. Without
    // the rule the plan is memory plus the new frame only (#1579 fix
    // round 3), so no read is needed. A frame that cannot be decoded is
    // not merged; a newer layout still fails the write below (fail
    // closed), and a damaged file is replaced by this write, as by the
    // first write after the quarantine.
    let file_frames = if KEEP {
        match crate::w3h_inline::fs::read(&path).await {
            Ok(existing) => decode(&existing).map(|log| log.frames).unwrap_or_default(),
            // A missing file is an empty plan. Any other read error must
            // not become one: planning from memory alone would let the
            // rename below drop the competing or crash-window frames the
            // file holds — the loss #1579 exists to prevent — so the
            // write fails closed and the caller treats it as not durable.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %path.display(),
                    "ADR 0110 S4: held frame log could not be read; the write fails closed"
                );
                return false;
            }
        }
    } else {
        Vec::new()
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

/// After a refused commit or install (rebind and owner recovery): remove
/// the refused commit — the revision and the result head — from the
/// group's log, and keep every other frame the file holds (#1579 fix
/// round 2): the competing pair at the head revision and the
/// crash-window frames memory has not installed are the evidence and the
/// restart links this log exists for. Best effort, as
/// [`rewrite_from_memory`]. Memory never holds the refused commit, so
/// the next write does not bring it back.
pub(in super::super) async fn rewrite_without<const CAP: usize, const KEEP: bool>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP, KEEP>,
    stable: &str,
    refused: (u64, &str),
) {
    if !host_commit_gate_open(state) {
        return;
    }
    let path = log_path(state, stable, extension);
    let write_lock = lock_file_writes(&path).await;
    let _serialized = write_lock.lock().await;
    let file_frames = match crate::w3h_inline::fs::read(&path).await {
        Ok(existing) => decode(&existing).map(|log| log.frames).unwrap_or_default(),
        // A missing file is an empty plan; any other read error keeps the
        // file as it is (best effort, but never lossy): rewriting from
        // memory alone could drop the evidence frames the file holds.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            tracing::warn!(
                %error,
                path = %path.display(),
                "ADR 0110 S4: held frame log could not be read; the refused frame is not un-written"
            );
            return;
        }
    };
    let log = held(&mut *state.revocation_evictions.inner.lock().await).planned_without(
        &file_frames,
        stable,
        refused,
    );
    let _durable = write_at(&path, &log).await;
}

/// After a refused install (crypto-only exclusion): write the group's log
/// as memory holds it, so the file does not keep the frame. That log
/// keeps no competing evidence (#1508 rule), and dropping its stale
/// file-only frames is what its catch-up round — which stops at the first
/// frame the head rule refuses — needs. Best effort: a restart drops such
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
        match crate::w3h_inline::fs::read(path).await {
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
        match crate::w3h_inline::fs::read(log_path(state, stable, extension)).await {
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
    /// skip an off-chain frame, keep a competing pair instead. In memory
    /// a received frame at a held revision is dropped and an authored one
    /// replaces it; in the file a write plans from memory plus the new
    /// frame, so a frame only the file had — at any revision — leaves
    /// with the write (#1579 fix round 3).
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

        // The file: the write plans from memory plus the new frame only
        // (#1579 fix round 3), so a stale frame that only the file held —
        // at the write's revision or any other — leaves with the write,
        // and the file still holds one frame per revision.
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
        assert_eq!(on_disk.len(), 1, "one frame per revision");
        assert_eq!(
            (
                on_disk[0].next_revision,
                on_disk[0].result_head.as_str(),
                on_disk[0].frame.as_slice()
            ),
            (5, "h5b", &[2][..]),
            "the received frame is durable; a frame only the file held leaves with the write"
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

    /// #1579 fix round 3: a `.celog` write plans from memory plus the new
    /// frame only, as before #1579. A stale frame only the file holds — a
    /// crash-window frame whose revision a different commit later took, so
    /// neither memory nor the new write claims it — must not survive the
    /// write: `restore` holds it (it is below the head, with no chain
    /// check), and the crypto-exclusion catch-up round stops at the first
    /// frame the head rule refuses, so the stale frame would strand every
    /// frame after it.
    #[tokio::test]
    async fn a_celog_write_drops_a_stale_file_frame_at_an_unclaimed_revision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("g.celog");
        // The crash window: a frame was written at revision 7, then its
        // install hit a local fault, and a different commit took revision
        // 7 — so the frame is stale, and memory claims its revision with
        // no frame of its own.
        let stale = ReplayLogV1 {
            stable_group_id: "g".to_string(),
            frames: vec![ReplayFrameV1 {
                next_revision: 7,
                result_head: "h7-stale".to_string(),
                authored: false,
                frame: vec![7],
            }],
        };
        assert!(write_at(&path, &stale).await);
        // A later write at revision 9, memory holding the installed frames
        // below the stale one.
        let mut memory = HeldLog::<16, false>::default();
        memory.remember("g", 6, "h6", Arc::new(vec![6]), false);
        let existing = file_frames_of(&path).await;
        let planned = memory.planned(&existing, "g", (9, "h9"), &Arc::new(vec![9]), false);
        assert!(write_at(&path, &planned).await);
        let on_disk = file_frames_of(&path).await;
        let held: Vec<(u64, &str)> = on_disk
            .iter()
            .map(|frame| (frame.next_revision, frame.result_head.as_str()))
            .collect();
        assert_eq!(
            held,
            vec![(6, "h6"), (9, "h9")],
            "a stale file-only frame at an unclaimed revision leaves with the write"
        );

        // The restart: the group's head has moved past the stale revision,
        // and the frames the round holds are the file's, so no stale frame
        // is held — nothing stops the round before the frames after it.
        let (local, survivor) = (crate::identity::AgentId([1; 32]), [2u8; 32]);
        let (stable, mut groups) = committed_group(local, survivor);
        let info = groups.get_mut(&stable).expect("group");
        info.state_revision = 10;
        info.state_hash = "h10".to_string();
        let mut after = HeldLog::<16, false>::default();
        let restored = after.restore(
            vec![ReplayLogV1 {
                stable_group_id: stable.clone(),
                frames: on_disk,
            }],
            &groups,
        );
        assert!(restored.received.is_empty());
        let served: Vec<String> = after
            .catchup_frames(std::slice::from_ref(&stable), 4)
            .into_iter()
            .map(|(_, head, _)| head)
            .collect();
        assert_eq!(
            served,
            vec!["h6".to_string(), "h9".to_string()],
            "the stale frame is not held after the restart"
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

    /// #1579 fix round 2: a refused commit or install removes its own
    /// frame and no other. After a restart with a competing pair on disk
    /// (memory holds neither), a later refused frame leaves the pair in
    /// the file — the evidence this log exists for. Memory holds the
    /// installed frame below the pair and never the refused commit: a
    /// frame is remembered only after its commit or install succeeds, and
    /// the rewrite does not bring the refused one back.
    #[tokio::test]
    async fn a_refused_frame_leaves_the_log_and_the_file_evidence_stays() {
        use crate::server::routes::named_groups as ng;
        fn rebind_held(inner: &mut S4Inner) -> &mut HeldLog<16, true> {
            &mut inner.rebind.log
        }
        let (state, _dir) = ng::tests::secure_endpoint_test_state()
            .await
            .expect("test state");
        // The installed frame below the pair: memory holds it, as after a
        // real install.
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .rebind
            .log
            .remember("g", 4, "h4", Arc::new(b"held".to_vec()), false);
        let pair = (Arc::new(b"first".to_vec()), Arc::new(b"second".to_vec()));
        assert!(
            write_received(
                &state,
                REBIND_EXTENSION,
                rebind_held,
                "g",
                (5, "h5a"),
                &pair.0
            )
            .await
        );
        assert!(
            write_received(
                &state,
                REBIND_EXTENSION,
                rebind_held,
                "g",
                (5, "h5b"),
                &pair.1
            )
            .await
        );
        // The crash window: the installs never happened, so memory holds
        // neither frame of the pair.
        let refused = Arc::new(b"refused".to_vec());
        assert!(
            write_received(
                &state,
                REBIND_EXTENSION,
                rebind_held,
                "g",
                (6, "h6"),
                &refused
            )
            .await
        );
        rewrite_without(&state, REBIND_EXTENSION, rebind_held, "g", (6, "h6")).await;
        let on_disk = frames_on_disk(&state, REBIND_EXTENSION, "g").await;
        let held: Vec<(u64, &str, &[u8])> = on_disk
            .iter()
            .map(|frame| {
                (
                    frame.next_revision,
                    frame.result_head.as_str(),
                    frame.frame.as_slice(),
                )
            })
            .collect();
        assert_eq!(
            held,
            vec![
                (4, "h4", b"held".as_slice()),
                (5, "h5a", b"first".as_slice()),
                (5, "h5b", b"second".as_slice())
            ],
            "the refused frame leaves; the competing pair stays as evidence"
        );
        let in_memory: Vec<String> = state
            .revocation_evictions
            .inner
            .lock()
            .await
            .rebind
            .log
            .catchup_frames(&["g".to_string()], 0)
            .into_iter()
            .map(|(_, head, _)| head)
            .collect();
        assert_eq!(
            in_memory,
            vec!["h4".to_string()],
            "memory never holds the refused commit"
        );
    }

    /// #1579 review: a log file the process cannot read — here a valid log
    /// with mode `0o000` — fails the write closed. A rename needs no read
    /// permission on the target, so a plan from memory alone would replace
    /// the file and drop the frames it holds; instead
    /// `write_received` answers `false` (the caller installs nothing) and
    /// `rewrite_without` leaves the file as it is. The file's bytes are
    /// the same after both calls.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_log_fails_the_write_closed() {
        use crate::server::routes::named_groups as ng;
        use std::os::unix::fs::PermissionsExt as _;
        fn rebind_held(inner: &mut S4Inner) -> &mut HeldLog<16, true> {
            &mut inner.rebind.log
        }
        let (state, _dir) = ng::tests::secure_endpoint_test_state()
            .await
            .expect("test state");
        state
            .revocation_evictions
            .inner
            .lock()
            .await
            .rebind
            .log
            .remember("g", 4, "h4", Arc::new(b"held".to_vec()), true);
        // A valid log that holds a competing pair, made unreadable.
        let path = log_path(&state, "g", REBIND_EXTENSION);
        let held_file = ReplayLogV1 {
            stable_group_id: "g".to_string(),
            frames: vec![
                ReplayFrameV1 {
                    next_revision: 5,
                    result_head: "h5a".to_string(),
                    authored: false,
                    frame: b"first".to_vec(),
                },
                ReplayFrameV1 {
                    next_revision: 5,
                    result_head: "h5b".to_string(),
                    authored: false,
                    frame: b"second".to_vec(),
                },
            ],
        };
        let bytes = encode(&held_file).expect("encode");
        std::fs::write(&path, &bytes).expect("write the log");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("the log is unreadable");
        assert!(
            !write_received(
                &state,
                REBIND_EXTENSION,
                rebind_held,
                "g",
                (6, "h6x"),
                &Arc::new(b"x".to_vec())
            )
            .await,
            "a read error other than NotFound fails the write"
        );
        rewrite_without(&state, REBIND_EXTENSION, rebind_held, "g", (4, "h4")).await;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("the log is readable again");
        assert_eq!(
            std::fs::read(&path).expect("read the log"),
            bytes,
            "neither call renamed over the unreadable log: the pair it holds is unchanged"
        );
    }

    /// #1579 review: the refused frame leaves before the per-revision
    /// bound counts, so it takes no place. The file holds three frames at
    /// revision 5 and the first is refused: the other two keep the two
    /// places and the refused one is gone — not the shape where the
    /// refused frame and the second consumed the bound and the valid
    /// third left.
    #[tokio::test]
    async fn the_refused_frame_takes_no_place_in_the_bound() {
        use crate::server::routes::named_groups as ng;
        fn rebind_held(inner: &mut S4Inner) -> &mut HeldLog<16, true> {
            &mut inner.rebind.log
        }
        let (state, _dir) = ng::tests::secure_endpoint_test_state()
            .await
            .expect("test state");
        for (head, bytes) in [
            ("h5a", b"a".to_vec()),
            ("h5b", b"b".to_vec()),
            ("h5c", b"c".to_vec()),
        ] {
            assert!(
                write_received(
                    &state,
                    REBIND_EXTENSION,
                    rebind_held,
                    "g",
                    (5, head),
                    &Arc::new(bytes)
                )
                .await
            );
        }
        rewrite_without(&state, REBIND_EXTENSION, rebind_held, "g", (5, "h5a")).await;
        let on_disk = frames_on_disk(&state, REBIND_EXTENSION, "g").await;
        let held: Vec<(u64, &str)> = on_disk
            .iter()
            .map(|frame| (frame.next_revision, frame.result_head.as_str()))
            .collect();
        assert_eq!(
            held,
            vec![(5, "h5b"), (5, "h5c")],
            "the refused frame took no place: the two valid frames stay"
        );
    }

    /// #1579 review: `rewrite_without` keeps the same two-file-only-frames
    /// bound as a write. The file holds four frames only it has at one
    /// revision and the first is refused: the refused frame leaves before
    /// the bound counts, so the second and the third keep the two places
    /// and the fourth leaves.
    #[tokio::test]
    async fn a_refusal_keeps_two_file_only_frames_at_the_refused_revision() {
        use crate::server::routes::named_groups as ng;
        fn rebind_held(inner: &mut S4Inner) -> &mut HeldLog<16, true> {
            &mut inner.rebind.log
        }
        let (state, _dir) = ng::tests::secure_endpoint_test_state()
            .await
            .expect("test state");
        // Four frames at one revision that only the file holds: the crash
        // window after four competing writes, before any install.
        let path = log_path(&state, "g", REBIND_EXTENSION);
        let frames_of = |heads: [&str; 4]| ReplayLogV1 {
            stable_group_id: "g".to_string(),
            frames: heads
                .into_iter()
                .enumerate()
                .map(|(at, head)| ReplayFrameV1 {
                    next_revision: 5,
                    result_head: head.to_string(),
                    authored: false,
                    frame: vec![at as u8 + 1],
                })
                .collect(),
        };
        assert!(
            write_at(&path, &frames_of(["h5a", "h5b", "h5c", "h5d"])).await,
            "the file holds four frames"
        );
        rewrite_without(&state, REBIND_EXTENSION, rebind_held, "g", (5, "h5a")).await;
        let on_disk = frames_on_disk(&state, REBIND_EXTENSION, "g").await;
        let held: Vec<(u64, &str)> = on_disk
            .iter()
            .map(|frame| (frame.next_revision, frame.result_head.as_str()))
            .collect();
        assert_eq!(
            held,
            vec![(5, "h5b"), (5, "h5c")],
            "the refusal keeps the next two file-only frames; the fourth leaves"
        );
    }

    /// #1579 fix round 2: the per-file write locks are held weakly, so a
    /// lock no write holds is reclaimed. Fix round 3: the map drops the
    /// dead entries at the next insert, so it is bounded by the logs being
    /// written, not by every log path this process ever wrote. The paths
    /// live under one prefix only this test uses, so the size assertions
    /// hold with the other tests' entries in the map too.
    #[tokio::test]
    async fn an_unused_write_lock_leaves_the_map() {
        let dir = "/evidence/lock-reclaim-rc3/";
        let path_of = |name: &str| PathBuf::from(format!("{dir}{name}.crblog"));
        let size = |locks: &HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>| {
            locks.keys().filter(|path| path.starts_with(dir)).count()
        };
        let first = lock_file_writes(&path_of("a")).await;
        let second = lock_file_writes(&path_of("a")).await;
        assert!(Arc::ptr_eq(&first, &second), "one lock per path while held");
        {
            let locks = FILE_WRITE_LOCKS.lock().await;
            assert_eq!(size(&locks), 1, "the held path has its entry");
        }
        let reclaimed = Arc::downgrade(&first);
        drop((first, second));
        let held = lock_file_writes(&path_of("b")).await;
        {
            let locks = FILE_WRITE_LOCKS.lock().await;
            assert_eq!(
                size(&locks),
                1,
                "a dead entry is dropped at the next insert, so the map holds only the paths being written"
            );
            assert!(
                locks.contains_key(&path_of("b")),
                "the path being written has its entry"
            );
        }
        assert!(
            reclaimed.upgrade().is_none(),
            "a lock no write holds is freed"
        );
        drop(held);
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
        crate::w3h_inline::fs::write(&damaged, b"X0XRPL1\0not a log")
            .await
            .expect("write");
        assert!(read_all_in(dir.path(), REBIND_EXTENSION, true)
            .await
            .is_empty());
        assert!(!damaged.exists(), "the damaged file is moved aside");
        let mut entries = crate::w3h_inline::fs::read_dir(dir.path())
            .await
            .expect("read_dir");
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
        crate::w3h_inline::fs::write(&newer, &bytes)
            .await
            .expect("write");
        assert!(read_all_in(dir.path(), REBIND_EXTENSION, true)
            .await
            .is_empty());
        assert!(
            !write_at(&newer, &log).await,
            "a newer layout blocks the commit"
        );
        assert_eq!(
            crate::w3h_inline::fs::read(&newer).await.expect("kept"),
            bytes
        );
    }
}
