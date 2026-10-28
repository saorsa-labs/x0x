//! ADR 0110 §4b(1) restart durability (#1625): the pending owner-recovery
//! mandates of one group.
//!
//! The owner node's `waiting_for_recovery_member` wait and the promoted
//! member's held mandate were memory-only, so a restart of either node
//! ended them: the recovery then depended on the owner's 5 s resend or a
//! fresh signature. Each node now keeps its side in a local file, written
//! through the shared durable writer behind the ADR 0094 host-commit gate,
//! and a restart loads it again.
//!
//! - **File.** `<data_dir>/treekem/<stem>.orcpend`, with the `.evjournal`
//!   stem rule. It is local state, not a wire format: the header
//!   `X0XORP1\0`, the postcard [`PendingOrcV1`], then the BLAKE3 hash of
//!   that body (the layout of the held frame logs,
//!   [`super::rebind::replay_log::encode_local_file`]). The mandates are
//!   the signed structures, not the wire bytes: the owner rebuilds its
//!   delivery and the member its held mandate from them.
//! - **Write.** Temp write, fsync, atomic rename and directory fsync,
//!   after the memory change (best effort: a failed write leaves the
//!   memory state as it is, and a restart then loses that side, as before
//!   this file existed). A file with a newer layout is never rewritten,
//!   so that side stays memory-only. A group with no pending side has no
//!   file: the last write retires it.
//! - **Load.** A damaged file is quarantined (ADR 0108 §5a) and its
//!   mandates are lost; a newer layout stays on disk, not loaded. Inside
//!   an ADR 0094 trial a damaged file is skipped and left in place (§5).
//!   A loaded mandate is installed only after it verifies against the
//!   loaded group again ([`super::owner_recovery`]): a restart never
//!   installs an unverified mandate, and a mandate whose group left its
//!   parent head stays dropped. A file whose sides can never apply again
//!   is retired at load, outside a trial.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::groups::eviction::SidecarDecodeError;
use crate::groups::owner_recovery::SignedOwnerRecoveryMandateV1;
use crate::server::state::AppState;

use super::rebind::replay_log::{decode_local_file, encode_local_file};

/// Extension of a group's pending-mandate file.
pub(super) const EXTENSION: &str = "orcpend";
const PREFIX: &[u8] = b"X0XORP";
const HEADER_V1: &[u8; 8] = b"X0XORP1\0";
const MAX_SUPPORTED_VERSION: u8 = 1;

/// The v1 file: the two pending mandates of one group. A node holds the
/// owner side, the member side, or neither; the two never name the same
/// local agent in one group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingOrcV1 {
    /// Stable group ID.
    pub(super) stable_group_id: String,
    /// The owner node's signed mandate while it waits for the member's
    /// commit (`waiting_for_recovery_member`).
    pub(super) owner_wait: Option<SignedOwnerRecoveryMandateV1>,
    /// The verified mandate the promoted member (this node) holds until
    /// it commits.
    pub(super) member_hold: Option<SignedOwnerRecoveryMandateV1>,
}

/// The file path of `stable_group_id`'s pending mandates.
pub(super) fn path(state: &AppState, stable_group_id: &str) -> PathBuf {
    super::evjournal_path(state, stable_group_id).with_extension(EXTENSION)
}

fn encode(file: &PendingOrcV1) -> Result<Vec<u8>, postcard::Error> {
    encode_local_file(HEADER_V1, file)
}

fn decode(bytes: &[u8]) -> Result<PendingOrcV1, SidecarDecodeError> {
    decode_local_file(PREFIX, MAX_SUPPORTED_VERSION, bytes)
}

/// Write `file` durably at its path. A file with a newer layout is never
/// rewritten. Returns whether `file` is durable.
pub(super) async fn write(state: &AppState, file: &PendingOrcV1) -> bool {
    let path = path(state, &file.stable_group_id);
    if let Ok(existing) = tokio::fs::read(&path).await {
        if let Err(SidecarDecodeError::NewerFormat(version)) = decode(&existing) {
            tracing::warn!(version, path = %path.display(), "ADR 0110 S4: pending mandates have a newer layout; not rewritten");
            return false;
        }
    }
    let Ok(bytes) = encode(file) else {
        return false;
    };
    match super::write_bytes_durably(&path, &bytes, None).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "ADR 0110 S4: pending mandate write failed");
            false
        }
    }
}

/// Retire the file of `stable_group_id`: the group holds no pending side.
/// Best effort; a restart re-drops what a stale file restores.
pub(super) async fn retire(state: &AppState, stable_group_id: &str) {
    super::remove_file_durably(&path(state, stable_group_id)).await;
}

/// Read every pending-mandate file. A damaged file is quarantined and
/// skipped; a newer layout is skipped and kept. Inside an ADR 0094 trial
/// (`gate_open` false) a damaged file is skipped and left in place (§5).
pub(super) async fn read_all(state: &AppState, gate_open: bool) -> Vec<PendingOrcV1> {
    let mut files = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(&state.treekem_dir).await else {
        return files;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(EXTENSION) {
            continue;
        }
        let Ok(bytes) = tokio::fs::read(&path).await else {
            continue;
        };
        match decode(&bytes) {
            Ok(file) => files.push(file),
            Err(SidecarDecodeError::NewerFormat(version)) => {
                tracing::warn!(version, path = %path.display(), "ADR 0110 S4: pending mandates have a newer layout; not loaded");
            }
            Err(SidecarDecodeError::Damaged(reason)) if !gate_open => {
                tracing::warn!(reason, path = %path.display(), "ADR 0110 S4: damaged pending mandates inside an ADR 0094 trial; not loaded and not quarantined");
            }
            Err(SidecarDecodeError::Damaged(reason)) => {
                tracing::warn!(reason, path = %path.display(), "ADR 0110 S4: damaged pending mandates; quarantining (ADR 0108 §5a); they are lost");
                match super::quarantine_file(&path, &bytes).await {
                    Ok((_, pending)) => {
                        super::finalize_quarantine(&pending).await;
                    }
                    Err(step) => {
                        tracing::warn!(step, path = %path.display(), "ADR 0110 S4: pending mandate quarantine failed");
                    }
                }
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> PendingOrcV1 {
        PendingOrcV1 {
            stable_group_id: "g".to_string(),
            owner_wait: None,
            member_hold: Some(SignedOwnerRecoveryMandateV1 {
                body: crate::groups::owner_recovery::OwnerRecoveryMandateBodyV1 {
                    stable_group_id: "g".to_string(),
                    parent_head: "h".to_string(),
                    parent_revision: 4,
                    revoked_admins: Vec::new(),
                    promoted: [7; 32],
                    promoted_certificate_digest: "cd".repeat(16),
                    owner_public_key: vec![1, 2, 3],
                    issued_at_ms: 42,
                },
                signature: vec![9; 8],
            }),
        }
    }

    /// The v1 file round-trips, and a flipped byte or a newer version
    /// digit never loads as a mandate (fail closed, as the other S4 files).
    #[test]
    fn pending_mandates_round_trip_and_reject_damage() {
        let pending = file();
        let bytes = encode(&pending).expect("encode");
        assert_eq!(decode(&bytes), Ok(pending));
        let mut damaged = bytes.clone();
        if let Some(last) = damaged.last_mut() {
            *last ^= 1;
        }
        assert!(matches!(
            decode(&damaged),
            Err(SidecarDecodeError::Damaged(_))
        ));
        let mut newer = bytes;
        newer[PREFIX.len()] = b'2';
        assert!(matches!(
            decode(&newer),
            Err(SidecarDecodeError::NewerFormat(2))
        ));
    }
}
