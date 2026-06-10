//! User identity CLI commands.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::identity::UserKeypair;
use crate::storage::{load_user_keypair_from, save_user_keypair_to};

/// Default user identity key path (`~/.x0x/user.key`).
pub fn default_user_key_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".x0x").join("user.key"))
}

/// `x0x user-id create [PATH]` — create a user identity keypair on disk.
pub async fn create(output: Option<PathBuf>) -> Result<PathBuf> {
    let path = match output {
        Some(path) => path,
        None => default_user_key_path()?,
    };

    let keypair = UserKeypair::generate()
        .map_err(|e| anyhow::anyhow!("failed to generate user keypair: {e}"))?;
    save_user_keypair_to(&keypair, &path)
        .await
        .with_context(|| format!("failed to write user keypair to {}", path.display()))?;

    Ok(path)
}

/// Report produced by `x0x user-id inspect`.
#[derive(Debug, serde::Serialize)]
pub struct InspectReport {
    /// Path of the inspected key file.
    pub path: String,
    /// Full hex-encoded UserId (SHA-256 of the ML-DSA-65 public key).
    pub user_id: String,
    /// Four-word speakable form of the UserId, when derivable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_words: Option<String>,
    /// Always true on success; failures return an error (non-zero exit).
    pub valid: bool,
}

/// `x0x user-id inspect [PATH]` — read and validate a user identity file.
///
/// Pure local file operation: deserialises the file as a [`UserKeypair`] and
/// reports the derived `user_id` and four-word form. Never requires a running
/// daemon — the symmetric counterpart of `x0x user-id create`.
pub async fn inspect(input: Option<PathBuf>) -> Result<InspectReport> {
    let path = match input {
        Some(path) => path,
        None => default_user_key_path()?,
    };

    let keypair = load_user_keypair_from(&path)
        .await
        .with_context(|| format!("invalid user identity file {}", path.display()))?;
    let user_id = hex::encode(keypair.user_id().as_bytes());
    let user_words = four_word_networking::IdentityEncoder::new()
        .encode_hex(&user_id)
        .ok()
        .map(|w| w.to_string());

    Ok(InspectReport {
        path: path.display().to_string(),
        user_id,
        user_words,
        valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[tokio::test]
    async fn create_writes_loadable_user_keypair() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("user.key");

        let resolved = create(Some(path.clone())).await?;

        ensure!(
            resolved == path,
            "resolved path should match requested path"
        );
        ensure!(path.is_file(), "user key file should exist");
        ensure!(
            path.metadata()?.len() > 0,
            "user key file should not be empty"
        );
        let loaded = load_user_keypair_from(&path).await?;
        let _user_id = loaded.user_id();

        Ok(())
    }

    #[tokio::test]
    async fn inspect_reports_user_id_and_words_for_valid_file() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path().join("user.key");
        create(Some(path.clone())).await?;
        let expected = hex::encode(load_user_keypair_from(&path).await?.user_id().as_bytes());

        let report = inspect(Some(path.clone())).await?;

        ensure!(report.valid, "valid file must report valid=true");
        ensure!(
            report.user_id == expected,
            "inspect must derive the same user_id the storage layer loads"
        );
        ensure!(
            report.user_words.is_some(),
            "a 32-byte user_id must yield a four-word form"
        );
        ensure!(
            report.path == path.display().to_string(),
            "report must echo the inspected path"
        );
        Ok(())
    }

    #[tokio::test]
    async fn inspect_missing_file_fails_naming_the_path() {
        let temp_dir = tempfile::tempdir().expect("tmpdir");
        let path = temp_dir.path().join("nope.key");

        let err = inspect(Some(path.clone()))
            .await
            .expect_err("missing file must fail");
        assert!(
            format!("{err:#}").contains(&path.display().to_string()),
            "error must identify the offending file: {err:#}"
        );
    }

    #[tokio::test]
    async fn inspect_malformed_file_fails() {
        let temp_dir = tempfile::tempdir().expect("tmpdir");
        let path = temp_dir.path().join("garbage.key");
        std::fs::write(&path, b"not-a-bincode-user-keypair").expect("write");

        assert!(
            inspect(Some(path)).await.is_err(),
            "malformed file must fail validation"
        );
    }
}
