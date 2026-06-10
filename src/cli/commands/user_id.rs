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
///
/// With `from_seed_hex` (issue #95), the keypair is derived
/// deterministically from the 32-byte seed via FIPS 204 seeded KeyGen:
/// same seed → same keypair on any machine. Without it, random keygen.
pub async fn create(output: Option<PathBuf>, from_seed_hex: Option<&str>) -> Result<PathBuf> {
    let path = match output {
        Some(path) => path,
        None => default_user_key_path()?,
    };

    let keypair = match from_seed_hex {
        Some(hex_seed) => {
            let bytes = hex::decode(hex_seed.trim())
                .context("--from-seed must be hex (64 hex chars encoding 32 bytes)")?;
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!(
                    "--from-seed must encode exactly 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )
            })?;
            UserKeypair::from_seed(&seed)
                .map_err(|e| anyhow::anyhow!("failed to derive user keypair from seed: {e}"))?
        }
        None => UserKeypair::generate()
            .map_err(|e| anyhow::anyhow!("failed to generate user keypair: {e}"))?,
    };
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

        let resolved = create(Some(path.clone()), None).await?;

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
        create(Some(path.clone()), None).await?;
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
    async fn create_from_seed_is_deterministic_across_machines() -> Result<()> {
        // Issue #95: same seed must yield the same UserKeypair every time —
        // this is the contract mnemonic-based identity portability rests on.
        let temp_dir = tempfile::tempdir()?;
        let seed_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

        let path_a = temp_dir.path().join("a.key");
        let path_b = temp_dir.path().join("b.key");
        create(Some(path_a.clone()), Some(seed_hex)).await?;
        create(Some(path_b.clone()), Some(seed_hex)).await?;

        let id_a = load_user_keypair_from(&path_a).await?.user_id();
        let id_b = load_user_keypair_from(&path_b).await?.user_id();
        ensure!(id_a == id_b, "same seed must derive the same user_id");

        let path_c = temp_dir.path().join("c.key");
        let other_seed = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        create(Some(path_c.clone()), Some(other_seed)).await?;
        let id_c = load_user_keypair_from(&path_c).await?.user_id();
        ensure!(
            id_a != id_c,
            "different seeds must derive different user_ids"
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_from_seed_rejects_bad_seed_encoding() {
        let temp_dir = tempfile::tempdir().expect("tmpdir");
        let path = temp_dir.path().join("user.key");

        assert!(
            create(Some(path.clone()), Some("not-hex")).await.is_err(),
            "non-hex seed must be rejected"
        );
        assert!(
            create(Some(path.clone()), Some("aabb")).await.is_err(),
            "short seed must be rejected"
        );
        assert!(
            !path.exists(),
            "no key file may be written when the seed is invalid"
        );
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
