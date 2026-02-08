use crate::crdt::persistence::backend::{
    CheckpointRequest, PersistenceBackend, PersistenceBackendError, PersistenceSnapshot,
};
use crate::crdt::persistence::migration::{resolve_legacy_artifact_outcome, ArtifactLoadOutcome};
use crate::crdt::persistence::policy::PersistenceMode;
use crate::crdt::persistence::snapshot::{SnapshotDecodeError, SnapshotEnvelope};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;

const SNAPSHOT_EXT: &str = "snapshot";

#[derive(Debug, Clone)]
pub struct FileSnapshotBackend {
    root: PathBuf,
    mode: PersistenceMode,
}

impl FileSnapshotBackend {
    #[must_use]
    pub fn new(root: PathBuf, mode: PersistenceMode) -> Self {
        Self { root, mode }
    }

    fn entity_dir(&self, entity_id: &str) -> PathBuf {
        self.root.join(entity_id)
    }

    fn quarantine_dir(&self, entity_id: &str) -> PathBuf {
        self.entity_dir(entity_id).join("quarantine")
    }

    fn snapshot_file_name(timestamp_millis: u128) -> String {
        format!("{:020}.{}", timestamp_millis, SNAPSHOT_EXT)
    }

    async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PersistenceBackendError> {
        let parent = path.parent().ok_or_else(|| {
            PersistenceBackendError::Operation("snapshot path is missing parent directory".to_string())
        })?;
        fs::create_dir_all(parent).await?;

        let temp_path = path.with_extension("tmp");
        let mut temp_file = fs::File::create(&temp_path).await?;
        temp_file.write_all(bytes).await?;
        temp_file.sync_all().await?;
        drop(temp_file);

        fs::rename(&temp_path, path).await?;

        let dir = fs::File::open(parent).await?;
        dir.sync_all().await?;
        Ok(())
    }

    async fn sorted_snapshots_newest_first(
        &self,
        entity_id: &str,
    ) -> Result<Vec<PathBuf>, PersistenceBackendError> {
        let dir = self.entity_dir(entity_id);
        if !fs::try_exists(&dir).await? {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(&dir).await?;
        let mut paths = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let is_snapshot = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == SNAPSHOT_EXT);
            if is_snapshot {
                paths.push(path);
            }
        }

        paths.sort();
        paths.reverse();
        Ok(paths)
    }

    async fn quarantine(
        &self,
        entity_id: &str,
        source: &Path,
        reason: &str,
    ) -> Result<(), PersistenceBackendError> {
        let quarantine_dir = self.quarantine_dir(entity_id);
        fs::create_dir_all(&quarantine_dir).await?;

        let file_name = source.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            PersistenceBackendError::Operation("invalid snapshot file name".to_string())
        })?;

        let destination = quarantine_dir.join(format!("{}-{}", reason, file_name));
        fs::rename(source, destination).await?;
        Ok(())
    }

    pub async fn list_entity_snapshots(
        &self,
        entity_id: &str,
    ) -> Result<Vec<PathBuf>, PersistenceBackendError> {
        self.sorted_snapshots_newest_first(entity_id).await
    }
}

#[async_trait]
impl PersistenceBackend for FileSnapshotBackend {
    async fn checkpoint(
        &self,
        request: &CheckpointRequest,
        snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        let timestamp_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PersistenceBackendError::Operation(e.to_string()))?
            .as_millis();

        let envelope = SnapshotEnvelope::new(snapshot.schema_version, snapshot.payload.clone());
        let encoded = envelope
            .encode()
            .map_err(|e| PersistenceBackendError::Operation(e.to_string()))?;

        let path = self
            .entity_dir(&request.entity_id)
            .join(Self::snapshot_file_name(timestamp_millis));
        Self::write_atomic(&path, &encoded).await
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        let snapshots = self.sorted_snapshots_newest_first(entity_id).await?;
        if snapshots.is_empty() {
            return Err(PersistenceBackendError::SnapshotNotFound(entity_id.to_string()));
        }

        for path in snapshots {
            let bytes = fs::read(&path).await?;
            match SnapshotEnvelope::decode(&bytes) {
                Ok((decoded, _migration_result)) => {
                    return Ok(PersistenceSnapshot {
                        entity_id: entity_id.to_string(),
                        schema_version: decoded.schema_version,
                        payload: decoded.payload,
                    });
                }
                Err(SnapshotDecodeError::Migration(
                    crate::crdt::persistence::migration::MigrationError::UnsupportedLegacyEncryptedArtifact,
                )) => {
                    let outcome = resolve_legacy_artifact_outcome(self.mode);
                    let path_display = path.display().to_string();
                    return match outcome {
                        ArtifactLoadOutcome::StrictFail(_) => {
                            Err(PersistenceBackendError::UnsupportedLegacyEncryptedArtifact {
                                path: path_display,
                            })
                        }
                        ArtifactLoadOutcome::DegradedSkip(_) => {
                            Err(PersistenceBackendError::DegradedSkippedLegacyArtifact {
                                path: path_display,
                            })
                        }
                        ArtifactLoadOutcome::Load(_) => {
                            Err(PersistenceBackendError::Operation(
                                "invalid artifact outcome for legacy encrypted snapshot".to_string(),
                            ))
                        }
                    };
                }
                Err(err) => {
                    self.quarantine(entity_id, &path, "corrupt").await?;
                    return Err(PersistenceBackendError::SnapshotCorrupt {
                        path: path.display().to_string(),
                        reason: err.to_string(),
                    });
                }
            }
        }

        Err(PersistenceBackendError::NoLoadableSnapshot(
            entity_id.to_string(),
        ))
    }

    async fn delete_entity(&self, entity_id: &str) -> Result<(), PersistenceBackendError> {
        let dir = self.entity_dir(entity_id);
        if fs::try_exists(&dir).await? {
            fs::remove_dir_all(dir).await?;
        }
        Ok(())
    }
}
