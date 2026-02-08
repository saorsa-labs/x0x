use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MANIFEST_FILE_NAME: &str = "store.manifest.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreManifest {
    pub schema_version: u32,
    pub store_id: String,
}

impl StoreManifest {
    #[must_use]
    pub fn v1(store_id: impl Into<String>) -> Self {
        Self {
            schema_version: 1,
            store_id: store_id.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest missing at {0}")]
    Missing(PathBuf),
    #[error("manifest serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("manifest I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn manifest_path(store_root: &Path) -> PathBuf {
    store_root.join(MANIFEST_FILE_NAME)
}

pub fn ensure_manifest(store_root: &Path, manifest: &StoreManifest) -> Result<(), ManifestError> {
    fs::create_dir_all(store_root)?;

    let path = manifest_path(store_root);
    if path.exists() {
        return Ok(());
    }

    let temp_path = store_root.join(format!("{}.tmp", MANIFEST_FILE_NAME));
    let bytes = serde_json::to_vec_pretty(manifest)?;

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temp_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&temp_path, &path)?;

    let dir = File::open(store_root)?;
    dir.sync_all()?;
    Ok(())
}

pub fn read_manifest(store_root: &Path) -> Result<StoreManifest, ManifestError> {
    let path = manifest_path(store_root);
    if !path.exists() {
        return Err(ManifestError::Missing(path));
    }

    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_create_read_is_idempotent() {
        let temp = tempfile::tempdir().expect("temp dir");
        let manifest = StoreManifest::v1("local-store");

        ensure_manifest(temp.path(), &manifest).expect("first ensure");
        ensure_manifest(temp.path(), &manifest).expect("second ensure");

        let loaded = read_manifest(temp.path()).expect("read manifest");
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn missing_manifest_reports_typed_error() {
        let temp = tempfile::tempdir().expect("temp dir");
        let err = read_manifest(temp.path()).expect_err("should be missing");
        assert!(matches!(err, ManifestError::Missing(_)));
    }
}
