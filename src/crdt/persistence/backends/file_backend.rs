use crate::crdt::persistence::backend::{
    CheckpointRequest, PersistenceBackend, PersistenceBackendError, PersistenceSnapshot,
};
use crate::crdt::persistence::health::{
    EVENT_CHECKPOINT_ATTEMPT, EVENT_CHECKPOINT_FAILURE, EVENT_CHECKPOINT_SUCCESS,
    EVENT_LEGACY_ARTIFACT_DETECTED,
};
use crate::crdt::persistence::migration::resolve_legacy_artifact_outcome;
use crate::crdt::persistence::policy::PersistenceMode;
use crate::crdt::persistence::snapshot::{SnapshotDecodeError, SnapshotEnvelope};
use crate::crdt::persistence::snapshot_filename::{
    snapshot_file_name, snapshot_timestamp_from_path,
};
use async_trait::async_trait;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;

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

    fn validate_entity_id(entity_id: &str) -> Result<(), PersistenceBackendError> {
        if entity_id.is_empty() {
            return Err(PersistenceBackendError::InvalidEntityId {
                entity_id: entity_id.to_string(),
                reason: "entity_id must not be empty".to_string(),
            });
        }

        if entity_id.contains('/') || entity_id.contains('\\') {
            return Err(PersistenceBackendError::InvalidEntityId {
                entity_id: entity_id.to_string(),
                reason: "path separators are not allowed".to_string(),
            });
        }

        if entity_id.contains('%') {
            return Err(PersistenceBackendError::InvalidEntityId {
                entity_id: entity_id.to_string(),
                reason: "percent-encoded path segments are not allowed".to_string(),
            });
        }

        let mut components = Path::new(entity_id).components();
        let Some(component) = components.next() else {
            return Err(PersistenceBackendError::InvalidEntityId {
                entity_id: entity_id.to_string(),
                reason: "entity_id path components are invalid".to_string(),
            });
        };

        if components.next().is_some() {
            return Err(PersistenceBackendError::InvalidEntityId {
                entity_id: entity_id.to_string(),
                reason: "nested paths are not allowed".to_string(),
            });
        }

        if !matches!(component, Component::Normal(_)) {
            return Err(PersistenceBackendError::InvalidEntityId {
                entity_id: entity_id.to_string(),
                reason: "absolute and traversal paths are not allowed".to_string(),
            });
        }

        Ok(())
    }

    fn entity_dir(&self, entity_id: &str) -> Result<PathBuf, PersistenceBackendError> {
        Self::validate_entity_id(entity_id)?;
        Ok(self.root.join(entity_id))
    }

    fn quarantine_dir(&self, entity_id: &str) -> Result<PathBuf, PersistenceBackendError> {
        Ok(self.entity_dir(entity_id)?.join("quarantine"))
    }

    async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PersistenceBackendError> {
        let parent = path.parent().ok_or_else(|| {
            PersistenceBackendError::Operation(
                "snapshot path is missing parent directory".to_string(),
            )
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
        let dir = self.entity_dir(entity_id)?;
        if !fs::try_exists(&dir).await? {
            return Ok(Vec::new());
        }

        let mut entries = fs::read_dir(&dir).await?;
        let mut snapshots = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(timestamp) = snapshot_timestamp_from_path(&path) {
                snapshots.push((timestamp, path));
            }
        }

        snapshots.sort_by(|left, right| right.0.cmp(&left.0));
        Ok(snapshots.into_iter().map(|(_, path)| path).collect())
    }

    async fn quarantine(
        &self,
        entity_id: &str,
        source: &Path,
        reason: &str,
    ) -> Result<(), PersistenceBackendError> {
        let quarantine_dir = self.quarantine_dir(entity_id)?;
        fs::create_dir_all(&quarantine_dir).await?;

        let file_name = source.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            PersistenceBackendError::Operation("invalid snapshot file name".to_string())
        })?;

        let destination = quarantine_dir.join(format!("{reason}-{file_name}"));
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
        tracing::info!(
            event = EVENT_CHECKPOINT_ATTEMPT,
            entity_id = request.entity_id,
            reason = format!("{:?}", request.reason),
            mutation_count = request.mutation_count
        );

        let timestamp_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PersistenceBackendError::Operation(e.to_string()))?
            .as_millis();

        let envelope = SnapshotEnvelope::new(snapshot.schema_version, snapshot.payload.clone());
        let encoded = envelope
            .encode()
            .map_err(|e| PersistenceBackendError::Operation(e.to_string()))?;

        let path = self
            .entity_dir(&request.entity_id)?
            .join(snapshot_file_name(timestamp_millis));
        match Self::write_atomic(&path, &encoded).await {
            Ok(()) => {
                tracing::info!(
                    event = EVENT_CHECKPOINT_SUCCESS,
                    entity_id = request.entity_id,
                    path = path.display().to_string(),
                    reason = format!("{:?}", request.reason)
                );
                Ok(())
            }
            Err(err) => {
                tracing::error!(
                    event = EVENT_CHECKPOINT_FAILURE,
                    entity_id = request.entity_id,
                    path = path.display().to_string(),
                    reason = format!("{:?}", request.reason),
                    error = err.to_string()
                );
                Err(err)
            }
        }
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        let snapshots = self.sorted_snapshots_newest_first(entity_id).await?;
        if snapshots.is_empty() {
            return Err(PersistenceBackendError::SnapshotNotFound(
                entity_id.to_string(),
            ));
        }

        for path in snapshots {
            let bytes = match fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(
                        event = "persistence.snapshot.skipped_unreadable",
                        mode = self.mode.as_str(),
                        path = path.display().to_string(),
                        reason = err.to_string()
                    );
                    continue;
                }
            };
            match SnapshotEnvelope::decode(&bytes) {
                Ok((decoded, migration_result)) => {
                    tracing::info!(
                        event = "persistence.migration.decision",
                        mode = self.mode.as_str(),
                        path = path.display().to_string(),
                        decision = format!("{:?}", migration_result)
                    );
                    return Ok(PersistenceSnapshot {
                        entity_id: entity_id.to_string(),
                        schema_version: decoded.schema_version,
                        payload: decoded.payload,
                    });
                }
                Err(SnapshotDecodeError::Migration(
                    crate::crdt::persistence::migration::MigrationError::UnsupportedLegacyEncryptedArtifact,
                )) => {
                    tracing::warn!(
                        event = EVENT_LEGACY_ARTIFACT_DETECTED,
                        mode = self.mode.as_str(),
                        path = path.display().to_string(),
                        outcome = format!("{:?}", resolve_legacy_artifact_outcome(self.mode))
                    );
                    continue;
                }
                Err(err) => {
                    self.quarantine(entity_id, &path, "corrupt").await?;
                    tracing::warn!(
                        event = "persistence.snapshot.skipped_corrupt",
                        mode = self.mode.as_str(),
                        path = path.display().to_string(),
                        reason = err.to_string()
                    );
                }
            }
        }

        Err(PersistenceBackendError::NoLoadableSnapshot(
            entity_id.to_string(),
        ))
    }

    async fn delete_entity(&self, entity_id: &str) -> Result<(), PersistenceBackendError> {
        let dir = self.entity_dir(entity_id)?;
        if fs::try_exists(&dir).await? {
            fs::remove_dir_all(dir).await?;
        }
        Ok(())
    }
}
