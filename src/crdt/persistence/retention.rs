use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tokio::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionOutcome {
    pub deleted_old_snapshots: usize,
    pub deleted_orphan_entities: usize,
}

impl RetentionOutcome {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            deleted_old_snapshots: 0,
            deleted_orphan_entities: 0,
        }
    }
}

pub async fn enforce_retention_cycle(
    store_root: &Path,
    active_entities: &[String],
    checkpoints_to_keep: u8,
) -> Result<RetentionOutcome, std::io::Error> {
    if !fs::try_exists(store_root).await? {
        return Ok(RetentionOutcome::empty());
    }

    let keep = usize::from(checkpoints_to_keep.max(1));
    let active: HashSet<&str> = active_entities.iter().map(String::as_str).collect();

    let mut outcome = RetentionOutcome::empty();
    let mut entries = fs::read_dir(store_root).await?;

    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        if !entry.file_type().await?.is_dir() {
            continue;
        }

        let Some(entity_id) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };

        if !active.contains(entity_id.as_str()) {
            fs::remove_dir_all(entry_path).await?;
            outcome.deleted_orphan_entities += 1;
            continue;
        }

        let deleted = trim_entity_snapshots(&entry_path, keep).await?;
        outcome.deleted_old_snapshots += deleted;
    }

    Ok(outcome)
}

pub async fn storage_usage_bytes(store_root: &Path) -> Result<u64, std::io::Error> {
    if !fs::try_exists(store_root).await? {
        return Ok(0);
    }

    let mut total = 0_u64;
    let mut stack = vec![PathBuf::from(store_root)];

    while let Some(next) = stack.pop() {
        let mut entries = fs::read_dir(next).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                total = total.saturating_add(entry.metadata().await?.len());
            }
        }
    }

    Ok(total)
}

async fn trim_entity_snapshots(entity_dir: &Path, keep: usize) -> Result<usize, std::io::Error> {
    let mut entries = fs::read_dir(entity_dir).await?;
    let mut snapshots = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let is_snapshot = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == "snapshot");
        if is_snapshot {
            snapshots.push(path);
        }
    }

    snapshots.sort();
    snapshots.reverse();

    let mut deleted = 0usize;
    for stale in snapshots.iter().skip(keep) {
        fs::remove_file(stale).await?;
        deleted += 1;
    }

    Ok(deleted)
}
