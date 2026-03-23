use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use sha2::{Digest, Sha256};

use super::manifest::{current_platform_target, ReleaseManifest};
use super::signature::{verify_bytes_signature_with_key, RELEASE_SIGNING_KEY};
use super::{UpgradeError, UpgradeResult, Upgrader};

/// Auto-apply upgrader that handles the full download → verify → extract → replace → restart flow.
pub struct AutoApplyUpgrader {
    /// Which binary to extract from the archive ("x0xd" or "x0x-bootstrap").
    binary_name: String,
    /// Exit cleanly for service manager restart instead of spawning new process.
    stop_on_upgrade: bool,
}

impl AutoApplyUpgrader {
    pub fn new(binary_name: &str) -> Self {
        Self {
            binary_name: binary_name.to_string(),
            stop_on_upgrade: false,
        }
    }

    pub fn with_stop_on_upgrade(mut self, stop: bool) -> Self {
        self.stop_on_upgrade = stop;
        self
    }

    /// Apply an upgrade from a `ReleaseManifest`.
    ///
    /// 1. Find the platform-appropriate asset
    /// 2. Download archive
    /// 3. Verify SHA-256 hash against manifest (integrity)
    /// 4. Download and verify ML-DSA-65 signature on archive (authenticity)
    /// 5. Extract binary from archive
    /// 6. Replace current binary with backup/rollback
    /// 7. Trigger restart
    pub async fn apply_upgrade_from_manifest(
        &self,
        manifest: &ReleaseManifest,
    ) -> Result<UpgradeResult, UpgradeError> {
        let current_version_str = crate::VERSION;
        let target_version = semver::Version::parse(&manifest.version)
            .map_err(|e| UpgradeError::Other(format!("invalid version: {e}")))?;
        let current_version = semver::Version::parse(current_version_str)
            .map_err(|e| UpgradeError::Other(format!("invalid current version: {e}")))?;

        info!(
            current_version = %current_version,
            target_version = %target_version,
            "Starting auto-apply upgrade from {} to {}",
            current_version,
            target_version
        );

        // Find platform asset
        let platform_target = current_platform_target().ok_or(UpgradeError::UnsupportedPlatform)?;

        let asset = manifest
            .matches_platform(platform_target)
            .ok_or(UpgradeError::NoPlatformAsset)?;

        let target_path = current_binary_path()?;
        let upgrader = Upgrader::new(target_path.clone(), current_version);
        let temp_dir = upgrader.create_temp_dir()?;

        let archive_path = temp_dir.join("archive");
        let sig_path = temp_dir.join("archive.sig");

        // Download archive
        info!(
            target = platform_target,
            "Downloading release archive for {}", platform_target
        );
        download_to_file(&asset.archive_url, &archive_path).await?;

        let archive_data =
            std::fs::read(&archive_path).map_err(|e| UpgradeError::Other(e.to_string()))?;

        // Verify archive SHA-256 against manifest (integrity)
        let actual_hash: [u8; 32] = Sha256::digest(&archive_data).into();
        if actual_hash != asset.archive_sha256 {
            warn!(
                expected = hex::encode(asset.archive_sha256),
                actual = hex::encode(actual_hash),
                "Archive SHA-256 mismatch"
            );
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(UpgradeError::HashMismatch);
        }
        info!("Archive SHA-256 verified against manifest");

        // Download and verify ML-DSA-65 signature on archive (authenticity)
        info!("Downloading signature...");
        download_to_file(&asset.signature_url, &sig_path).await?;
        let sig_data = std::fs::read(&sig_path).map_err(|e| UpgradeError::Other(e.to_string()))?;

        if let Err(e) =
            verify_bytes_signature_with_key(&archive_data, &sig_data, RELEASE_SIGNING_KEY)
        {
            warn!(error = %e, "Signature verification failed");
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(e.into());
        }
        info!("Archive signature verified successfully");

        // Extract binary from archive
        // On Windows, also check for binary_name.exe
        let binary_name = if cfg!(target_os = "windows") && !self.binary_name.ends_with(".exe") {
            format!("{}.exe", self.binary_name)
        } else {
            self.binary_name.clone()
        };
        info!("Extracting binary from archive...");
        let extracted_path = temp_dir.join("extracted-binary");
        extract_binary_from_archive(&archive_path, &extracted_path, &binary_name)?;

        // Replace binary (with backup + rollback)
        let result = upgrader.perform_upgrade(&extracted_path, &target_version)?;

        // Clean up temp dir
        if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
            debug!("Failed to clean temp dir: {e}");
        }

        if matches!(result, UpgradeResult::Success { .. }) {
            info!(
                version = %target_version,
                "Successfully upgraded to version {}",
                target_version
            );
            self.trigger_restart(&target_path);
        }

        Ok(result)
    }

    /// Trigger a restart after successful upgrade.
    fn trigger_restart(&self, binary_path: &Path) {
        if self.stop_on_upgrade {
            // Service manager mode: exit with code 0, let systemd restart
            let exit_code = if cfg!(windows) { 100 } else { 0 };
            info!(
                exit_code = exit_code,
                "Exiting with code {} for service manager restart", exit_code
            );
            std::process::exit(exit_code);
        } else {
            // Standalone mode: spawn new process with same args, exit old
            let args: Vec<OsString> = std::env::args_os().skip(1).collect();
            let args_display: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().to_string())
                .collect();
            info!(
                binary_path = %binary_path.display(),
                args = %args_display.join(" "),
                "Spawning new process: {} {}",
                binary_path.display(),
                args_display.join(" ")
            );

            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let error = std::process::Command::new(binary_path)
                    .args(&args)
                    .arg("--skip-update-check")
                    .exec();
                // exec() only returns on error
                warn!(error = %error, "exec failed: {error}");
            }

            #[cfg(not(unix))]
            {
                match std::process::Command::new(binary_path)
                    .args(&args)
                    .arg("--skip-update-check")
                    .spawn()
                {
                    Ok(_) => std::process::exit(0),
                    Err(e) => warn!(error = %e, "Failed to spawn new process: {e}"),
                }
            }
        }
    }
}

/// Get the path to the currently running binary.
///
/// Handles the `/proc/self/exe (deleted)` suffix on Linux.
pub fn current_binary_path() -> Result<PathBuf, UpgradeError> {
    let exe = std::env::current_exe()
        .map_err(|e| UpgradeError::Other(format!("failed to resolve current executable: {e}")))?;

    // On Linux, /proc/self/exe can have " (deleted)" suffix after an upgrade
    let path_str = exe.to_string_lossy();
    if path_str.ends_with(" (deleted)") {
        let clean = path_str.trim_end_matches(" (deleted)");
        Ok(PathBuf::from(clean))
    } else {
        Ok(exe)
    }
}

/// Download a URL to a local file, enforcing a maximum size limit.
///
/// Checks `Content-Length` upfront and streams the response to disk with
/// a running byte counter to prevent OOM on oversized payloads.
async fn download_to_file(url: &str, destination: &Path) -> Result<(), UpgradeError> {
    use super::MAX_BINARY_SIZE_BYTES;
    use futures::StreamExt;
    use std::io::Write;

    debug!(url = url, "Downloading: {url}");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| UpgradeError::DownloadError(e.to_string()))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| {
            warn!(error = %e, "Archive download failed: {e}");
            UpgradeError::DownloadError(e.to_string())
        })?
        .error_for_status()
        .map_err(|e| {
            warn!(error = %e, "Archive download failed: {e}");
            UpgradeError::DownloadError(e.to_string())
        })?;

    // Reject early if Content-Length exceeds limit
    if let Some(content_length) = response.content_length() {
        if content_length > MAX_BINARY_SIZE_BYTES {
            return Err(UpgradeError::BinaryTooLarge {
                size: content_length,
                limit: MAX_BINARY_SIZE_BYTES,
            });
        }
    }

    // Stream to disk with running byte counter
    let mut file = std::fs::File::create(destination)
        .map_err(|e| UpgradeError::DownloadError(format!("create file failed: {e}")))?;
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes =
            chunk_result.map_err(|e| UpgradeError::DownloadError(e.to_string()))?;
        downloaded += chunk.len() as u64;
        if downloaded > MAX_BINARY_SIZE_BYTES {
            drop(file);
            let _ = std::fs::remove_file(destination);
            return Err(UpgradeError::BinaryTooLarge {
                size: downloaded,
                limit: MAX_BINARY_SIZE_BYTES,
            });
        }
        file.write_all(&chunk)
            .map_err(|e| UpgradeError::DownloadError(format!("write failed: {e}")))?;
    }

    debug!(
        bytes = downloaded,
        path = %destination.display(),
        "Downloaded {} bytes to {}",
        downloaded,
        destination.display()
    );

    Ok(())
}

/// Extract a binary from an archive (tar.gz or zip, detected by magic bytes).
fn extract_binary_from_archive(
    archive_path: &Path,
    output_path: &Path,
    binary_name: &str,
) -> Result<(), UpgradeError> {
    let data = std::fs::read(archive_path)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to read archive: {e}")))?;

    // Detect archive format by magic bytes
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        // gzip magic bytes -> tar.gz
        extract_from_tar_gz(archive_path, output_path, binary_name)
    } else if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        // PK zip magic bytes
        extract_from_zip(archive_path, output_path, binary_name)
    } else {
        Err(UpgradeError::ExtractionError(
            "unknown archive format (not tar.gz or zip)".to_string(),
        ))
    }
}

fn extract_from_tar_gz(
    archive_path: &Path,
    output_path: &Path,
    binary_name: &str,
) -> Result<(), UpgradeError> {
    let file = std::fs::File::open(archive_path)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to open archive: {e}")))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    for entry_result in archive
        .entries()
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to read tar entries: {e}")))?
    {
        let mut entry = entry_result
            .map_err(|e| UpgradeError::ExtractionError(format!("bad tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| UpgradeError::ExtractionError(format!("bad entry path: {e}")))?;

        let path_str = path.to_string_lossy();
        // Match binary by filename (last component) or full path
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if file_name == binary_name || path_str.ends_with(binary_name) {
            debug!(archive_path = %path_str, "Found binary in tar.gz archive: {}", path_str);
            let mut output = std::fs::File::create(output_path).map_err(|e| {
                UpgradeError::ExtractionError(format!("failed to create output: {e}"))
            })?;
            std::io::copy(&mut entry, &mut output).map_err(|e| {
                UpgradeError::ExtractionError(format!("failed to extract binary: {e}"))
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(output_path, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| {
                        UpgradeError::ExtractionError(format!("failed to set permissions: {e}"))
                    })?;
            }

            return Ok(());
        }
    }

    Err(UpgradeError::ExtractionError(format!(
        "binary '{binary_name}' not found in tar.gz archive"
    )))
}

fn extract_from_zip(
    archive_path: &Path,
    output_path: &Path,
    binary_name: &str,
) -> Result<(), UpgradeError> {
    let file = std::fs::File::open(archive_path)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to open archive: {e}")))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| UpgradeError::ExtractionError(format!("failed to open zip: {e}")))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| UpgradeError::ExtractionError(format!("bad zip entry: {e}")))?;

        let entry_name = entry.name().to_string();
        let file_name = Path::new(&entry_name)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if file_name == binary_name || entry_name.ends_with(binary_name) {
            let mut output = std::fs::File::create(output_path).map_err(|e| {
                UpgradeError::ExtractionError(format!("failed to create output: {e}"))
            })?;
            std::io::copy(&mut entry, &mut output).map_err(|e| {
                UpgradeError::ExtractionError(format!("failed to extract binary: {e}"))
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(output_path, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| {
                        UpgradeError::ExtractionError(format!("failed to set permissions: {e}"))
                    })?;
            }

            return Ok(());
        }
    }

    Err(UpgradeError::ExtractionError(format!(
        "binary '{binary_name}' not found in zip archive"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_tar_gz(dir: &Path, binary_name: &str, content: &[u8]) -> PathBuf {
        let archive_path = dir.join("test.tar.gz");
        let file = std::fs::File::create(&archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);

        let inner_path = format!("x0x-linux-x64-gnu/{binary_name}");
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, &inner_path, content)
            .unwrap();
        builder.finish().unwrap();

        archive_path
    }

    fn create_test_zip(dir: &Path, binary_name: &str, content: &[u8]) -> PathBuf {
        let archive_path = dir.join("test.zip");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file(binary_name, options).unwrap();
        zip.write_all(content).unwrap();
        zip.finish().unwrap();

        archive_path
    }

    #[test]
    fn test_extract_from_tar_gz() {
        let dir = TempDir::new().unwrap();
        let archive = create_test_tar_gz(dir.path(), "x0xd", b"fake binary content");
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive, &output, "x0xd").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"fake binary content");
    }

    #[test]
    fn test_extract_from_zip() {
        let dir = TempDir::new().unwrap();
        let archive = create_test_zip(dir.path(), "x0xd.exe", b"fake windows binary");
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive, &output, "x0xd.exe").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"fake windows binary");
    }

    #[test]
    fn test_extract_nested_path() {
        let dir = TempDir::new().unwrap();
        // create_test_tar_gz puts it at x0x-linux-x64-gnu/x0xd
        let archive = create_test_tar_gz(dir.path(), "x0x-bootstrap", b"bootstrap binary");
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive, &output, "x0x-bootstrap").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"bootstrap binary");
    }

    #[test]
    fn test_unknown_archive_format_rejected() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("fake.bin");
        std::fs::write(&archive, b"not an archive").unwrap();
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
    }

    #[test]
    fn test_missing_binary_in_tar_gz() {
        let dir = TempDir::new().unwrap();
        let archive = create_test_tar_gz(dir.path(), "other-binary", b"content");
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
    }

    #[test]
    fn test_missing_binary_in_zip() {
        let dir = TempDir::new().unwrap();
        let archive = create_test_zip(dir.path(), "other.exe", b"content");
        let output = dir.path().join("extracted");

        let result = extract_binary_from_archive(&archive, &output, "x0xd.exe");
        assert!(matches!(result, Err(UpgradeError::ExtractionError(_))));
    }

    #[test]
    fn test_current_binary_path_resolves() {
        // Should resolve to something on any platform
        let path = current_binary_path().unwrap();
        assert!(path.is_absolute() || !path.to_string_lossy().is_empty());
    }
}
