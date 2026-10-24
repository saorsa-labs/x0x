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
//!   occur either (fail closed).
//! - **Load.** A damaged file is quarantined (ADR 0108 §5a: pending name,
//!   then history name), and that group starts with an empty log: its
//!   frames are lost, the load never panics and never uses the damaged
//!   bytes. A newer layout stays on disk, not loaded. A frame that is not
//!   on this node's loaded chain is not held (a crash between the write and
//!   the commit). An authored frame that is still the group's head gets
//!   its delivery again. A received frame above the loaded head (a crash
//!   between the write and the install) is received again: the caller
//!   puts it through the full receive checks.
//! - **Retire.** The file holds the group's in-memory log, with the same
//!   bound, so a frame leaves the file only when that bound drops it.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
/// group, by revision, deduplicated.
#[derive(Debug, Default)]
pub(in super::super) struct HeldLog<const CAP: usize> {
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

impl<const CAP: usize> HeldLog<CAP> {
    /// Keep a frame. A received frame never replaces a held frame of the
    /// same revision; an authored frame does, because it is the one on
    /// this node's chain.
    pub(in super::super) fn remember(
        &mut self,
        stable_group_id: &str,
        next_revision: u64,
        result_head: &str,
        bytes: Arc<Vec<u8>>,
        authored: bool,
    ) {
        let log = self.log.entry(stable_group_id.to_string()).or_default();
        if let Some(at) = log.iter().position(|e| e.next_revision == next_revision) {
            if !authored {
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

    /// The file of the group after it also holds the frame, with the
    /// [`Self::remember`] rule.
    fn planned(
        &self,
        stable: &str,
        (revision, head): (u64, &str),
        bytes: &Arc<Vec<u8>>,
        authored: bool,
    ) -> ReplayLogV1 {
        let mut scratch = Self::default();
        if let Some(log) = self.log.get(stable) {
            scratch.log.insert(stable.to_string(), log.clone());
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
pub(in super::super) async fn write_planned<const CAP: usize>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP>,
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
pub(in super::super) async fn write_received<const CAP: usize>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP>,
    stable: &str,
    at: (u64, &str),
    bytes: &Arc<Vec<u8>>,
) -> bool {
    write_with(state, extension, held, stable, at, bytes, false).await
}

async fn write_with<const CAP: usize>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP>,
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
    let planned = held(&mut *state.revocation_evictions.inner.lock().await)
        .planned(stable, at, bytes, authored);
    write_at(&log_path(state, stable, extension), &planned).await
}

/// After a failed local commit: write the group's log as memory holds it,
/// so the file does not keep the frame. Best effort: a restart drops such
/// a frame too.
pub(in super::super) async fn rewrite_from_memory<const CAP: usize>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP>,
    stable: &str,
) {
    if !host_commit_gate_open(state) {
        return;
    }
    let log = held(&mut *state.revocation_evictions.inner.lock().await).file(stable);
    let _durable = write_at(&log_path(state, stable, extension), &log).await;
}

/// Load the files once per process, before this node serves catch-up,
/// delivers, receives or authors a frame of this kind. Returns the frames
/// to deliver or receive again (empty when another call did the load).
pub(in super::super) async fn ensure_restored<const CAP: usize>(
    state: &AppState,
    extension: &str,
    held: impl Fn(&mut S4Inner) -> &mut HeldLog<CAP>,
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
        let mut before = HeldLog::<CAP>::default();
        before.remember(stable, 4, "h4", Arc::new(vec![4]), false);
        assert!(write_at(&path, &before.planned(stable, (5, "h5"), frame, true)).await);
        // The commit lands, then the process dies: `before` is lost.
        drop(before);
        let mut after = HeldLog::<CAP>::default();
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
        let planned = after.planned(stable, (6, "h6"), &Arc::new(vec![6]), true);
        assert!(write_at(&path, &planned).await);
        let mut again = HeldLog::<CAP>::default();
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
