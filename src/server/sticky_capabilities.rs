//! #2135: the durable copy of the capability store's sticky registry bits
//! (`<data_dir>/sticky-capabilities.json`).
//!
//! The removal-binding gate must not fall back to the legacy binding while a
//! member that once advertised `removal_commit_binding_v1` is offline, is
//! partitioned or withholds its advert past the 900 s advert TTL; that is
//! when two admins race. The record is per agent, not per group: the bit is
//! a property of the agent's binary. It is loaded at startup and written
//! only when an agent or its bits are added or dropped.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::state::AppState;
use crate::dm_capability::StickySeen;
use crate::identity::AgentId;

const FILE_NAME: &str = "sticky-capabilities.json";
const FORMAT_VERSION: u32 = 1;
const WRITE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, Deserialize)]
struct StickyFile {
    version: u32,
    entries: Vec<StickyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StickyEntry {
    agent_id: String,
    bits: u64,
    last_seen_unix_ms: u64,
}

pub(super) fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

fn decode(bytes: &[u8]) -> Option<Vec<(AgentId, StickySeen)>> {
    let file: StickyFile = serde_json::from_slice(bytes).ok()?;
    if file.version != FORMAT_VERSION {
        return None;
    }
    Some(
        file.entries
            .into_iter()
            .filter_map(|entry| {
                let bytes: [u8; 32] = hex::decode(&entry.agent_id).ok()?.try_into().ok()?;
                Some((
                    AgentId(bytes),
                    StickySeen {
                        bits: entry.bits,
                        last_seen_unix_ms: entry.last_seen_unix_ms,
                    },
                ))
            })
            .collect(),
    )
}

fn encode(entries: &[(AgentId, StickySeen)]) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&StickyFile {
        version: FORMAT_VERSION,
        entries: entries
            .iter()
            .map(|(agent, seen)| StickyEntry {
                agent_id: hex::encode(agent.as_bytes()),
                bits: seen.bits,
                last_seen_unix_ms: seen.last_seen_unix_ms,
            })
            .collect(),
    })
}

/// Seed the capability store from the file. A missing file is the normal
/// first start. An unreadable file is left in place and ignored: the gate
/// then seals the legacy binding until fresh adverts arrive, as before.
pub(super) async fn load(state: &AppState) {
    load_into(&state.data_dir, &state.agent.capability_store()).await;
}

/// [`load`] from `data_dir` into `store`.
pub(super) async fn load_into(data_dir: &Path, store: &crate::dm_capability::CapabilityStore) {
    let path = path_in(data_dir);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(path = %path.display(), "sticky capability record is not readable: {error}");
            return;
        }
    };
    match decode(&bytes) {
        Some(entries) => store.seed_sticky(entries),
        None => {
            tracing::warn!(path = %path.display(), "sticky capability record has an unknown format; ignored");
        }
    }
}

/// Write the record (temp file, fsync, rename, directory fsync).
pub(super) async fn write(
    data_dir: &Path,
    entries: &[(AgentId, StickySeen)],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = encode(entries).map_err(std::io::Error::other)?;
    let path = path_in(data_dir);
    let temp = path.with_file_name(format!("{FILE_NAME}.tmp"));
    let mut file = tokio::fs::File::create(&temp).await?;
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temp, &path).await?;
    if let Ok(dir) = tokio::fs::File::open(data_dir).await {
        let _ = dir.sync_all().await;
    }
    Ok(())
}

/// Persist the record whenever its generation changes.
pub(super) async fn run_writer(state: Arc<AppState>) {
    let mut written = state.agent.capability_store().sticky_snapshot().0;
    loop {
        tokio::time::sleep(WRITE_INTERVAL).await;
        let (generation, entries) = state.agent.capability_store().sticky_snapshot();
        if generation == written {
            continue;
        }
        match write(&state.data_dir, &entries).await {
            Ok(()) => written = generation,
            Err(error) => {
                tracing::warn!("sticky capability record not written: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_record_round_trips_through_its_file() {
        let dir = tempfile::tempdir().expect("dir");
        let entries = vec![(
            AgentId([7; 32]),
            StickySeen {
                bits: crate::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1,
                last_seen_unix_ms: 42,
            },
        )];
        write(dir.path(), &entries).await.expect("write");
        let bytes = tokio::fs::read(path_in(dir.path())).await.expect("read");
        assert_eq!(decode(&bytes), Some(entries));
        assert_eq!(decode(b"{\"version\":2,\"entries\":[]}"), None);
    }
}
