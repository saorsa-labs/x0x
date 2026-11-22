//! #2135: the durable copy of the capability store's sticky registry bits
//! (`<data_dir>/sticky-capabilities.json`).
//!
//! The removal-binding gate must not fall back to the legacy binding while a
//! member that once advertised `removal_commit_binding_v1` is offline, is
//! partitioned or withholds its advert past the 900 s advert TTL; that is
//! when two admins race. The record is per agent, because the bit is a
//! property of the agent's binary, and it holds only the Active and Pending
//! members of the groups this node is in, so mesh traffic from other agents
//! never adds or removes a record. It is loaded at startup and written only
//! when it changes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::state::AppState;
use crate::dm_capability::StickySeen;
use crate::groups::{GroupInfo, GroupMemberState};
use crate::identity::AgentId;

const FILE_NAME: &str = "sticky-capabilities.json";
const FORMAT_VERSION: u32 = 1;
const WRITE_INTERVAL: Duration = Duration::from_secs(5);
/// A file larger than this is not read. The record holds only local group
/// members, so a real file is far smaller.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct StickyFile {
    version: u32,
    entries: Vec<StickyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StickyEntry {
    agent_id: String,
    bits: u64,
    advert_created_at_unix_ms: u64,
}

pub(super) fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

fn decode(bytes: &[u8]) -> Option<Vec<(AgentId, StickySeen)>> {
    let file: StickyFile = serde_json::from_slice(bytes).ok()?;
    if file.version != FORMAT_VERSION {
        return None;
    }
    let mut entries = Vec::with_capacity(file.entries.len());
    for entry in file.entries {
        let parsed: Option<[u8; 32]> = hex::decode(&entry.agent_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok());
        match parsed {
            Some(bytes) => entries.push((
                AgentId(bytes),
                StickySeen {
                    bits: entry.bits,
                    advert_created_at_unix_ms: entry.advert_created_at_unix_ms,
                },
            )),
            None => tracing::warn!(
                agent_id = %entry.agent_id,
                "sticky capability record: entry with a bad agent id skipped"
            ),
        }
    }
    Some(entries)
}

fn encode(entries: &[(AgentId, StickySeen)]) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&StickyFile {
        version: FORMAT_VERSION,
        entries: entries
            .iter()
            .map(|(agent, seen)| StickyEntry {
                agent_id: hex::encode(agent.as_bytes()),
                bits: seen.bits,
                advert_created_at_unix_ms: seen.advert_created_at_unix_ms,
            })
            .collect(),
    })
}

/// The Active and Pending members of every group in which `local` is an
/// Active or Pending member.
pub(super) fn local_member_scope<'a>(
    groups: impl IntoIterator<Item = &'a GroupInfo>,
    local: &AgentId,
) -> Vec<AgentId> {
    let live = |state: GroupMemberState| {
        matches!(state, GroupMemberState::Active | GroupMemberState::Pending)
    };
    let local_hex = hex::encode(local.as_bytes());
    groups
        .into_iter()
        .filter(|info| {
            !info.withdrawn
                && info
                    .members_v2
                    .get(&local_hex)
                    .is_some_and(|member| live(member.state))
        })
        .flat_map(|info| info.members_v2.values())
        .filter(|member| live(member.state))
        .filter_map(|member| {
            let bytes: [u8; 32] = hex::decode(&member.agent_id).ok()?.try_into().ok()?;
            Some(AgentId(bytes))
        })
        .collect()
}

async fn refresh_scope(state: &AppState) {
    let scope = {
        let groups = state.named_groups.read().await;
        local_member_scope(groups.values(), &state.agent.agent_id())
    };
    state.agent.capability_store().set_sticky_scope(scope);
}

/// Seed `store` from the file in `data_dir`. A missing file is the normal
/// first start. An unreadable, oversized or unknown-format file is left in
/// place and ignored: the gate then uses current adverts until they arrive.
pub(super) async fn load_into(data_dir: &Path, store: &crate::dm_capability::CapabilityStore) {
    let path = path_in(data_dir);
    match tokio::fs::metadata(&path).await {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => {
            tracing::warn!(path = %path.display(), "sticky capability record is too large; ignored");
            return;
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(path = %path.display(), "sticky capability record is not readable: {error}");
            return;
        }
    }
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
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

/// Write the record: a new temp file (mode 0600, never through an existing
/// path or link), fsync, rename, directory fsync.
pub(super) async fn write(
    data_dir: &Path,
    entries: &[(AgentId, StickySeen)],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = encode(entries).map_err(std::io::Error::other)?;
    let path = path_in(data_dir);
    let temp = path.with_file_name(format!("{FILE_NAME}.tmp"));
    match tokio::fs::remove_file(&temp).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temp).await?;
    file.write_all(&bytes).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temp, &path).await?;
    if let Ok(dir) = tokio::fs::File::open(data_dir).await {
        let _ = dir.sync_all().await;
    }
    Ok(())
}

/// Each `interval`: refresh the scope from this node's groups, then persist
/// the record if it changed.
async fn run_writer(state: Arc<AppState>, interval: Duration, mut written: u64) {
    loop {
        tokio::time::sleep(interval).await;
        refresh_scope(&state).await;
        let (generation, entries) = state.agent.capability_store().sticky_snapshot();
        if generation == written {
            continue;
        }
        match write(&state.data_dir, &entries).await {
            Ok(()) => written = generation,
            Err(error) => tracing::warn!("sticky capability record not written: {error}"),
        }
    }
}

/// Startup: set the scope from the loaded groups, seed the record from its
/// file, and start the writer. The removal routes read the record, so this
/// runs before the workers that seal removals.
pub(super) async fn start(state: &Arc<AppState>) -> tokio::task::JoinHandle<()> {
    start_with_interval(state, WRITE_INTERVAL).await
}

pub(super) async fn start_with_interval(
    state: &Arc<AppState>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    refresh_scope(state).await;
    let store = state.agent.capability_store();
    load_into(&state.data_dir, &store).await;
    // The first tick writes once, so the file matches the scoped record.
    tokio::spawn(run_writer(Arc::clone(state), interval, u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_record_round_trips_through_its_file_with_mode_0600() {
        let dir = tempfile::tempdir().expect("dir");
        let entries = vec![(
            AgentId([7; 32]),
            StickySeen {
                bits: crate::dm::CapabilityRegistry::REMOVAL_COMMIT_BINDING_V1,
                advert_created_at_unix_ms: 42,
            },
        )];
        write(dir.path(), &entries).await.expect("write");
        write(dir.path(), &entries).await.expect("rewrite");
        let bytes = tokio::fs::read(path_in(dir.path())).await.expect("read");
        assert_eq!(decode(&bytes), Some(entries));
        assert_eq!(decode(b"{\"version\":2,\"entries\":[]}"), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path_in(dir.path()))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_bad_entry_is_skipped_and_the_rest_load() {
        let bytes = br#"{"version":1,"entries":[{"agent_id":"zz","bits":4194304,"advert_created_at_unix_ms":1},{"agent_id":"0707070707070707070707070707070707070707070707070707070707070707","bits":4194304,"advert_created_at_unix_ms":2}]}"#;
        let entries = decode(bytes).expect("decodes");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, AgentId([7; 32]));
    }
}
