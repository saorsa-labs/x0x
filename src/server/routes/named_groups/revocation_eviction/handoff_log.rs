//! ADR 0110 §1a and §2 restart durability (#1508 review): the kept expiry
//! hand-offs.
//!
//! §1a keeps a verified expiry hand-off that arrives before this node's
//! clock passes the raw `not_after` (or before the seat's bytes arrive),
//! and starts T_obs when both hold. §2 requires the earliest verified
//! hand-off receipt to be persisted. A kept hand-off has no `.evs` row
//! yet, so it is kept in its own local file and a restart loads it again.
//!
//! - **File.** `<data_dir>/revocation-evictions.evh`. It is local state,
//!   not a wire format: the header `X0XEHK1\0`, the postcard
//!   [`KeptHandoffsV1`], then the BLAKE3 hash of that body (the layout of
//!   the held frame logs, [`encode_local_file`]).
//! - **Write.** Temp write, fsync, atomic rename and directory fsync. A
//!   file with a newer layout is never rewritten; the kept hand-offs then
//!   stay in memory only, which can only make this node act later.
//! - **Load.** A damaged file is quarantined (ADR 0108 §5a) and its kept
//!   hand-offs are lost: the node falls back to its own trigger at
//!   `not_after + τ`. A newer layout stays on disk, not loaded.
//! - **Retire.** The file holds the in-memory set. The worker rewrites it
//!   after the `.evs` write that holds the rows the hand-offs opened.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::groups::eviction::{EvictionKey, SidecarDecodeError};
use crate::server::state::AppState;

use super::rebind::replay_log::{decode_local_file, encode_local_file};
use super::ExpiryHandoff;

/// The file name in the data directory.
const FILE_NAME: &str = "revocation-evictions.evh";
const PREFIX: &[u8] = b"X0XEHK";
const HEADER_V1: &[u8; 8] = b"X0XEHK1\0";
const MAX_SUPPORTED_VERSION: u8 = 1;

/// One kept hand-off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeptHandoffV1 {
    stable_group_id: String,
    target: [u8; 32],
    /// The committed digest that the hand-off names.
    certificate_digest: String,
    /// The verified receipt time (Unix ms).
    received_unix_ms: u64,
}

/// The v1 file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeptHandoffsV1 {
    handoffs: Vec<KeptHandoffV1>,
}

fn path(state: &AppState) -> PathBuf {
    state.data_dir.join(FILE_NAME)
}

fn encode(kept: &BTreeMap<EvictionKey, ExpiryHandoff>) -> Result<Vec<u8>, postcard::Error> {
    let file = KeptHandoffsV1 {
        handoffs: kept
            .iter()
            .map(|(key, handoff)| KeptHandoffV1 {
                stable_group_id: key.stable_group_id.clone(),
                target: key.target,
                certificate_digest: handoff.certificate_digest.clone(),
                received_unix_ms: handoff.received_unix_ms,
            })
            .collect(),
    };
    encode_local_file(HEADER_V1, &file)
}

fn decode(bytes: &[u8]) -> Result<BTreeMap<EvictionKey, ExpiryHandoff>, SidecarDecodeError> {
    let file: KeptHandoffsV1 = decode_local_file(PREFIX, MAX_SUPPORTED_VERSION, bytes)?;
    Ok(file
        .handoffs
        .into_iter()
        .map(|kept| {
            (
                EvictionKey::new(kept.stable_group_id, kept.target),
                ExpiryHandoff {
                    certificate_digest: kept.certificate_digest,
                    received_unix_ms: kept.received_unix_ms,
                },
            )
        })
        .collect())
}

/// Write the kept hand-offs when they changed since the last write.
pub(super) async fn persist(state: &AppState) {
    // §5: no write inside an ADR 0094 trial; the set stays dirty.
    if !super::host_commit_gate_open(state) {
        return;
    }
    let runtime = &state.revocation_evictions;
    let _writer = runtime.evs_writer.lock().await;
    let bytes = {
        let mut inner = runtime.inner.lock().await;
        if !inner.expiry_handoffs_dirty || inner.expiry_handoffs_newer_file {
            return;
        }
        inner.expiry_handoffs_dirty = false;
        encode(&inner.expiry_handoffs)
    };
    let written = match bytes {
        Ok(bytes) => super::write_bytes_durably(&path(state), &bytes, None)
            .await
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    if let Err(error) = written {
        tracing::warn!(%error, "ADR 0110 S4: kept expiry hand-off write failed; retrying");
        runtime.inner.lock().await.expiry_handoffs_dirty = true;
    }
}

/// Load the kept hand-offs at startup. A damaged file is quarantined; a
/// newer layout is kept on disk and never rewritten. Inside an ADR 0094
/// trial (`gate_open` false) a damaged file is left as it is; the load
/// after host commit quarantines it (§5).
pub(super) async fn load(state: &AppState, gate_open: bool) {
    let path = path(state);
    let Ok(bytes) = crate::w3h_inline::fs::read(&path).await else {
        return;
    };
    let loaded = match decode(&bytes) {
        Ok(kept) => kept,
        Err(SidecarDecodeError::NewerFormat(version)) => {
            tracing::warn!(
                version,
                "ADR 0110 S4: kept expiry hand-offs have a newer layout; not loaded"
            );
            state
                .revocation_evictions
                .inner
                .lock()
                .await
                .expiry_handoffs_newer_file = true;
            return;
        }
        Err(SidecarDecodeError::Damaged(reason)) if !gate_open => {
            tracing::warn!(reason, "ADR 0110 S4: damaged kept expiry hand-offs inside an ADR 0094 trial; quarantine waits for host commit");
            return;
        }
        Err(SidecarDecodeError::Damaged(reason)) => {
            tracing::warn!(reason, "ADR 0110 S4: damaged kept expiry hand-offs; quarantining (ADR 0108 §5a); they are lost");
            match super::quarantine_file(&path, &bytes).await {
                Ok((_, pending)) => {
                    super::finalize_quarantine(&pending).await;
                }
                Err(step) => {
                    tracing::warn!(step, "ADR 0110 S4: kept expiry hand-off quarantine failed");
                }
            }
            return;
        }
    };
    let mut inner = state.revocation_evictions.inner.lock().await;
    for (key, handoff) in loaded {
        inner.expiry_handoffs.entry(key).or_insert(handoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_handoffs_round_trip_and_reject_damage() {
        let kept = BTreeMap::from([(
            EvictionKey::new("g", [7; 32]),
            ExpiryHandoff {
                certificate_digest: "ab".repeat(32),
                received_unix_ms: 42,
            },
        )]);
        let bytes = encode(&kept).expect("encode");
        let back = decode(&bytes).expect("decode");
        let handoff = back.get(&EvictionKey::new("g", [7; 32])).expect("kept");
        assert_eq!(handoff.received_unix_ms, 42);
        assert_eq!(handoff.certificate_digest, "ab".repeat(32));
        let mut damaged = bytes.clone();
        if let Some(last) = damaged.last_mut() {
            *last ^= 1;
        }
        assert!(matches!(
            decode(&damaged),
            Err(SidecarDecodeError::Damaged(_))
        ));
        let mut newer = bytes;
        newer[6] = b'2';
        assert!(matches!(
            decode(&newer),
            Err(SidecarDecodeError::NewerFormat(2))
        ));
    }
}
