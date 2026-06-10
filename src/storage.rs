//! Key storage utilities for x0x identity persistence.
//!
//! This module provides serialization and storage functionality for
//! MachineKeypair, AgentKeypair, UserKeypair, and AgentCertificate types,
//! enabling persistence of identities across application restarts.

use crate::error::{IdentityError, Result};
use crate::identity::{AgentCertificate, AgentKeypair, MachineKeypair, UserKeypair};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs;

/// Serialized keypair representation for storage.
///
/// Uses raw bytes for efficiency rather than base64 encoding.
#[derive(Serialize, Deserialize)]
struct SerializedKeypair {
    /// Raw public key bytes
    public_key: Vec<u8>,
    /// Raw secret key bytes  
    secret_key: Vec<u8>,
}

/// Serialize a MachineKeypair to bytes for storage.
///
/// # Arguments
///
/// * `kp` - The MachineKeypair to serialize
///
/// # Returns
///
/// A vector containing the serialized keypair data
pub fn serialize_machine_keypair(kp: &MachineKeypair) -> Result<Vec<u8>> {
    let data = SerializedKeypair {
        public_key: kp.public_key().as_bytes().to_vec(),
        secret_key: kp.secret_key().as_bytes().to_vec(),
    };
    bincode::serialize(&data).map_err(|e| IdentityError::Serialization(e.to_string()))
}

/// Deserialize a MachineKeypair from bytes.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair data
///
/// # Returns
///
/// A deserialized MachineKeypair
pub fn deserialize_machine_keypair(bytes: &[u8]) -> Result<MachineKeypair> {
    let data: SerializedKeypair =
        bincode::deserialize(bytes).map_err(|e| IdentityError::Serialization(e.to_string()))?;
    MachineKeypair::from_bytes(&data.public_key, &data.secret_key)
}

/// Serialize an AgentKeypair to bytes for storage.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to serialize
///
/// # Returns
///
/// A vector containing the serialized keypair data
pub fn serialize_agent_keypair(kp: &AgentKeypair) -> Result<Vec<u8>> {
    let data = SerializedKeypair {
        public_key: kp.public_key().as_bytes().to_vec(),
        secret_key: kp.secret_key().as_bytes().to_vec(),
    };
    bincode::serialize(&data).map_err(|e| IdentityError::Serialization(e.to_string()))
}

/// Deserialize an AgentKeypair from bytes.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair data
///
/// # Returns
///
/// A deserialized AgentKeypair
pub fn deserialize_agent_keypair(bytes: &[u8]) -> Result<AgentKeypair> {
    let data: SerializedKeypair =
        bincode::deserialize(bytes).map_err(|e| IdentityError::Serialization(e.to_string()))?;
    AgentKeypair::from_bytes(&data.public_key, &data.secret_key)
}

/// x0x configuration directory path.
const X0X_DIR: &str = ".x0x";

/// Machine keypair file name.
const MACHINE_KEY_FILE: &str = "machine.key";

/// Agent keypair file name.
const AGENT_KEY_FILE: &str = "agent.key";

/// User keypair file name.
const USER_KEY_FILE: &str = "user.key";

/// Agent certificate file name.
const AGENT_CERT_FILE: &str = "agent.cert";

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

async fn write_private_file(path: &Path, bytes: Vec<u8>) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .await
        .map_err(IdentityError::from)?;

    let file_name = path.file_name().ok_or_else(|| {
        IdentityError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid path: missing file name",
        ))
    })?;
    let unique = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        unique
    ));

    fs::write(&tmp_path, bytes)
        .await
        .map_err(IdentityError::from)?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&tmp_path)
            .await
            .map_err(IdentityError::from)?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp_path, perms)
            .await
            .map_err(IdentityError::from)?;
    }

    if let Err(err) = fs::rename(&tmp_path, path).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(IdentityError::from(err));
    }

    Ok(())
}

/// Write arbitrary secret bytes to `path` with the same protection x0x gives
/// key material: an atomic write (temp file + rename) with Unix mode `0600`.
///
/// Used to persist TreeKEM group snapshots at rest (ADR-0012 §6 / Phase 4) —
/// they contain private key material and are no more sensitive than
/// `machine.key` / `agent.key` / `agent_kem.key`, which use this same model.
/// At-rest encryption of the whole identity dir is tracked separately
/// (ADR-0012 open question #4).
///
/// # Errors
/// Returns an error if the directory cannot be created or the write/rename
/// fails.
pub async fn write_private_bytes(path: &Path, bytes: Vec<u8>) -> Result<()> {
    write_private_file(path, bytes).await
}

/// Get the x0x configuration directory path.
///
/// # Returns
///
/// The path to the .x0x directory in the user's home directory
async fn x0x_dir() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        IdentityError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "home directory not found",
        ))
    })?;
    Ok(home.join(X0X_DIR))
}

/// Save a MachineKeypair to the default storage location.
///
/// Stores the keypair in ~/.x0x/machine.key with appropriate
/// file permissions. The directory will be created if it doesn't exist.
///
/// # Arguments
///
/// * `kp` - The MachineKeypair to save
///
/// # Returns
///
/// Ok(()) on success, or an error if the operation fails
pub async fn save_machine_keypair(kp: &MachineKeypair) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(MACHINE_KEY_FILE);
    let bytes = serialize_machine_keypair(kp)?;
    write_private_file(&path, bytes).await
}

/// Load a MachineKeypair from the default storage location.
///
/// # Returns
///
/// The loaded MachineKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_machine_keypair() -> Result<MachineKeypair> {
    let path = x0x_dir().await?.join(MACHINE_KEY_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    deserialize_machine_keypair(&bytes)
}

/// Check if a machine keypair exists in the default storage location.
///
/// # Returns
///
/// true if the machine key file exists, false otherwise
pub async fn machine_keypair_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    tokio::fs::try_exists(path.join(MACHINE_KEY_FILE))
        .await
        .unwrap_or(false)
}

/// Save an AgentKeypair to the specified file path.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to save
/// * `path` - The file path to save to
///
/// # Returns
///
/// Ok(()) on success, or an error if the operation fails
pub async fn save_agent_keypair<P: AsRef<Path>>(kp: &AgentKeypair, path: P) -> Result<()> {
    let bytes = serialize_agent_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Save a MachineKeypair to the specified file path.
///
/// Creates the parent directory if it doesn't exist.
///
/// # Arguments
///
/// * `kp` - The MachineKeypair to save
/// * `path` - The file path to save to
///
/// # Returns
///
/// `Ok(())` on success, or an error if file I/O fails
pub async fn save_machine_keypair_to<P: AsRef<Path> + Clone>(
    kp: &MachineKeypair,
    path: P,
) -> Result<()> {
    let bytes = serialize_machine_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load a MachineKeypair from the specified file path.
///
/// # Arguments
///
/// * `path` - The file path to load from
///
/// # Returns
///
/// The loaded MachineKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_machine_keypair_from<P: AsRef<Path>>(path: P) -> Result<MachineKeypair> {
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_machine_keypair(&bytes)
}

/// Load an AgentKeypair from the specified file path.
///
/// # Arguments
///
/// * `path` - The file path to load from
///
/// # Returns
///
/// The loaded AgentKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_agent_keypair<P: AsRef<Path>>(path: P) -> Result<AgentKeypair> {
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_agent_keypair(&bytes)
}

/// Save an AgentKeypair to the default storage location.
///
/// Stores the keypair in `~/.x0x/agent.key` with appropriate
/// file permissions. The directory will be created if it doesn't exist.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to save
///
/// # Returns
///
/// `Ok(())` on success, or an error if the operation fails
pub async fn save_agent_keypair_default(kp: &AgentKeypair) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(AGENT_KEY_FILE);
    let bytes = serialize_agent_keypair(kp)?;
    write_private_file(&path, bytes).await
}

/// Load an AgentKeypair from the default storage location.
///
/// # Returns
///
/// The loaded AgentKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_agent_keypair_default() -> Result<AgentKeypair> {
    let path = x0x_dir().await?.join(AGENT_KEY_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    deserialize_agent_keypair(&bytes)
}

/// Check if an agent keypair exists in the default storage location.
///
/// # Returns
///
/// true if the agent key file exists, false otherwise
pub async fn agent_keypair_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    tokio::fs::try_exists(path.join(AGENT_KEY_FILE))
        .await
        .unwrap_or(false)
}

/// Save an AgentKeypair to the specified file path.
///
/// Creates the parent directory if it doesn't exist. Sets file
/// permissions to 0o600 on Unix systems.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to save
/// * `path` - The file path to save to
///
/// # Returns
///
/// `Ok(())` on success, or an error if file I/O fails
pub async fn save_agent_keypair_to<P: AsRef<Path> + Clone>(
    kp: &AgentKeypair,
    path: P,
) -> Result<()> {
    let bytes = serialize_agent_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load an AgentKeypair from the specified file path.
///
/// # Arguments
///
/// * `path` - The file path to load from
///
/// # Returns
///
/// The loaded AgentKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_agent_keypair_from<P: AsRef<Path>>(path: P) -> Result<AgentKeypair> {
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_agent_keypair(&bytes)
}

// ── UserKeypair storage ──

/// Serialize a UserKeypair to bytes for storage.
///
/// # Arguments
///
/// * `kp` - The UserKeypair to serialize
///
/// # Returns
///
/// A vector containing the serialized keypair data
pub fn serialize_user_keypair(kp: &UserKeypair) -> Result<Vec<u8>> {
    let data = SerializedKeypair {
        public_key: kp.public_key().as_bytes().to_vec(),
        secret_key: kp.secret_key().as_bytes().to_vec(),
    };
    bincode::serialize(&data).map_err(|e| IdentityError::Serialization(e.to_string()))
}

/// Deserialize a UserKeypair from bytes.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair data
///
/// # Returns
///
/// A deserialized UserKeypair
pub fn deserialize_user_keypair(bytes: &[u8]) -> Result<UserKeypair> {
    let data: SerializedKeypair =
        bincode::deserialize(bytes).map_err(|e| IdentityError::Serialization(e.to_string()))?;
    UserKeypair::from_bytes(&data.public_key, &data.secret_key)
}

/// Save a UserKeypair to the default storage location (`~/.x0x/user.key`).
///
/// # Arguments
///
/// * `kp` - The UserKeypair to save
pub async fn save_user_keypair(kp: &UserKeypair) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(USER_KEY_FILE);
    let bytes = serialize_user_keypair(kp)?;
    write_private_file(&path, bytes).await
}

/// Load a UserKeypair from the default storage location (`~/.x0x/user.key`).
pub async fn load_user_keypair() -> Result<UserKeypair> {
    let path = x0x_dir().await?.join(USER_KEY_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    deserialize_user_keypair(&bytes)
}

/// Check if a user keypair exists in the default storage location.
pub async fn user_keypair_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    tokio::fs::try_exists(path.join(USER_KEY_FILE))
        .await
        .unwrap_or(false)
}

/// Save a UserKeypair to the specified file path.
///
/// Creates the parent directory if it doesn't exist. Sets file
/// permissions to 0o600 on Unix systems.
pub async fn save_user_keypair_to<P: AsRef<Path> + Clone>(kp: &UserKeypair, path: P) -> Result<()> {
    let bytes = serialize_user_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load a UserKeypair from the specified file path.
pub async fn load_user_keypair_from<P: AsRef<Path>>(path: P) -> Result<UserKeypair> {
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_user_keypair(&bytes)
}

// ── AgentCertificate storage ──

/// Save an AgentCertificate to the default storage location (`~/.x0x/agent.cert`).
pub async fn save_agent_certificate(cert: &AgentCertificate) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(AGENT_CERT_FILE);
    let bytes =
        bincode::serialize(cert).map_err(|e| IdentityError::Serialization(e.to_string()))?;
    write_private_file(&path, bytes).await
}

/// Load an AgentCertificate from the default storage location (`~/.x0x/agent.cert`).
pub async fn load_agent_certificate() -> Result<AgentCertificate> {
    let path = x0x_dir().await?.join(AGENT_CERT_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    bincode::deserialize(&bytes).map_err(|e| IdentityError::Serialization(e.to_string()))
}

/// Check if an agent certificate exists in the default storage location.
pub async fn agent_certificate_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    tokio::fs::try_exists(path.join(AGENT_CERT_FILE))
        .await
        .unwrap_or(false)
}

/// Save an AgentCertificate to the specified file path.
pub async fn save_agent_certificate_to<P: AsRef<Path> + Clone>(
    cert: &AgentCertificate,
    path: P,
) -> Result<()> {
    let bytes =
        bincode::serialize(cert).map_err(|e| IdentityError::Serialization(e.to_string()))?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load an AgentCertificate from the specified file path.
pub async fn load_agent_certificate_from<P: AsRef<Path>>(path: P) -> Result<AgentCertificate> {
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
    bincode::deserialize(&bytes).map_err(|e| IdentityError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AgentKeypair, MachineKeypair};

    #[tokio::test]
    async fn test_keypair_serialization_roundtrip() {
        // Test MachineKeypair
        let original = MachineKeypair::generate().unwrap();
        let serialized = serialize_machine_keypair(&original).unwrap();
        let deserialized = deserialize_machine_keypair(&serialized).unwrap();

        assert_eq!(original.machine_id(), deserialized.machine_id());
        assert_eq!(
            original.public_key().as_bytes(),
            deserialized.public_key().as_bytes()
        );

        // Test AgentKeypair
        let original_agent = AgentKeypair::generate().unwrap();
        let serialized_agent = serialize_agent_keypair(&original_agent).unwrap();
        let deserialized_agent = deserialize_agent_keypair(&serialized_agent).unwrap();

        assert_eq!(original_agent.agent_id(), deserialized_agent.agent_id());
        assert_eq!(
            original_agent.public_key().as_bytes(),
            deserialized_agent.public_key().as_bytes()
        );
    }

    #[tokio::test]
    async fn test_save_and_load_machine_keypair() {
        let keypair = MachineKeypair::generate().unwrap();

        // Save to temp file
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_machine.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        // Load and verify
        let loaded = load_machine_keypair_from_path(&path).await.unwrap();
        assert_eq!(keypair.machine_id(), loaded.machine_id());
    }

    #[tokio::test]
    async fn test_machine_keypair_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join(MACHINE_KEY_FILE);

        // Initially should not exist
        assert!(!machine_keypair_exists_in_dir(temp_dir.path()).await);

        // Create a key file
        let keypair = MachineKeypair::generate().unwrap();
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        // Should now exist
        assert!(machine_keypair_exists_in_dir(temp_dir.path()).await);
    }

    #[tokio::test]
    async fn test_invalid_deserialization() {
        // Test with invalid bytes
        let result = deserialize_machine_keypair(&[1u8, 2u8, 3u8]).unwrap_err();
        assert!(matches!(result, IdentityError::Serialization(_)));
    }

    // ── File permission tests (Unix only) ─────────────────────────────

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_file_has_restrictive_permissions() {
        let keypair = MachineKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_machine.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "key file must have 0600 permissions, got {:o}",
            mode
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_agent_key_file_has_restrictive_permissions() {
        let keypair = AgentKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_agent.key");
        save_agent_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "agent key file must have 0600 permissions, got {:o}",
            mode
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_file_not_world_readable() {
        let keypair = MachineKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        // World-readable bit (others read) must not be set
        assert_eq!(mode & 0o004, 0, "key file must not be world-readable");
        // Group-readable bit must not be set
        assert_eq!(mode & 0o040, 0, "key file must not be group-readable");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_file_not_world_writable() {
        let keypair = MachineKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        // World-writable bit must not be set
        assert_eq!(mode & 0o002, 0, "key file must not be world-writable");
    }

    #[cfg(unix)]
    async fn save_agent_keypair_to_path(kp: &AgentKeypair, path: &Path) -> Result<()> {
        let bytes = serialize_agent_keypair(kp)?;
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent)
            .await
            .map_err(IdentityError::from)?;
        fs::write(path, bytes).await.map_err(IdentityError::from)?;

        // Apply restrictive permissions (mirrors production code)
        let mut perms = fs::metadata(path)
            .await
            .map_err(IdentityError::from)?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .await
            .map_err(IdentityError::from)?;

        Ok(())
    }

    // Helper functions for testing (since the main functions use ~/.x0x)
    async fn save_machine_keypair_to_path(kp: &MachineKeypair, path: &Path) -> Result<()> {
        let bytes = serialize_machine_keypair(kp)?;
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent)
            .await
            .map_err(IdentityError::from)?;
        fs::write(path, bytes).await.map_err(IdentityError::from)?;

        // Apply restrictive permissions (mirrors production code path)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(path)
                .await
                .map_err(IdentityError::from)?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)
                .await
                .map_err(IdentityError::from)?;
        }

        Ok(())
    }

    async fn load_machine_keypair_from_path(path: &Path) -> Result<MachineKeypair> {
        let bytes = fs::read(path).await.map_err(IdentityError::from)?;
        deserialize_machine_keypair(&bytes)
    }

    async fn machine_keypair_exists_in_dir(dir: &Path) -> bool {
        dir.join(MACHINE_KEY_FILE).exists()
    }
}
