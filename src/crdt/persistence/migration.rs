use crate::crdt::persistence::policy::PersistenceMode;

pub const CURRENT_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationResult {
    Current,
    MigrateFromPrevious,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MigrationError {
    #[error(
        "unsupported snapshot schema version {found}; supported range is [{min_supported}, {max_supported}]"
    )]
    UnsupportedSchemaVersion {
        found: u32,
        min_supported: u32,
        max_supported: u32,
    },
    #[error("unsupported legacy encrypted snapshot artifact")]
    UnsupportedLegacyEncryptedArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactLoadOutcome {
    Load(MigrationResult),
    StrictFail(MigrationError),
    DegradedSkip(MigrationError),
}

pub fn evaluate_snapshot_schema(schema_version: u32) -> Result<MigrationResult, MigrationError> {
    if schema_version == CURRENT_SNAPSHOT_SCHEMA_VERSION {
        return Ok(MigrationResult::Current);
    }

    if schema_version + 1 == CURRENT_SNAPSHOT_SCHEMA_VERSION {
        return Ok(MigrationResult::MigrateFromPrevious);
    }

    Err(MigrationError::UnsupportedSchemaVersion {
        found: schema_version,
        min_supported: CURRENT_SNAPSHOT_SCHEMA_VERSION - 1,
        max_supported: CURRENT_SNAPSHOT_SCHEMA_VERSION,
    })
}

#[must_use]
pub fn resolve_legacy_artifact_outcome(mode: PersistenceMode) -> ArtifactLoadOutcome {
    let err = MigrationError::UnsupportedLegacyEncryptedArtifact;
    match mode {
        PersistenceMode::Strict => ArtifactLoadOutcome::StrictFail(err),
        PersistenceMode::Degraded => ArtifactLoadOutcome::DegradedSkip(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_accept_reject_matrix() {
        assert_eq!(
            evaluate_snapshot_schema(CURRENT_SNAPSHOT_SCHEMA_VERSION).expect("current version"),
            MigrationResult::Current
        );

        assert_eq!(
            evaluate_snapshot_schema(CURRENT_SNAPSHOT_SCHEMA_VERSION - 1)
                .expect("previous version"),
            MigrationResult::MigrateFromPrevious
        );

        let old = evaluate_snapshot_schema(CURRENT_SNAPSHOT_SCHEMA_VERSION - 2)
            .expect_err("too old must be rejected");
        assert!(matches!(
            old,
            MigrationError::UnsupportedSchemaVersion { .. }
        ));

        let future = evaluate_snapshot_schema(CURRENT_SNAPSHOT_SCHEMA_VERSION + 1)
            .expect_err("future version must be rejected");
        assert!(matches!(
            future,
            MigrationError::UnsupportedSchemaVersion { .. }
        ));
    }

    #[test]
    fn unsupported_legacy_artifacts_are_mode_deterministic() {
        assert_eq!(
            resolve_legacy_artifact_outcome(PersistenceMode::Strict),
            ArtifactLoadOutcome::StrictFail(MigrationError::UnsupportedLegacyEncryptedArtifact)
        );
        assert_eq!(
            resolve_legacy_artifact_outcome(PersistenceMode::Degraded),
            ArtifactLoadOutcome::DegradedSkip(MigrationError::UnsupportedLegacyEncryptedArtifact)
        );
    }
}
