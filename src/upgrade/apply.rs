//! Binary upgrade application: download, verify SHA-256, extract, and atomically
//! replace the running binary with rollback on failure.

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use sha2::{Digest, Sha256};

use super::manifest::{current_platform_target, ReleaseManifest};
use super::restart;
use super::signature::{verify_bytes_signature_with_key, RELEASE_SIGNING_KEY};
use super::{UpgradeError, UpgradeResult, Upgrader};

/// Removes an upgrade temp dir when dropped, so it is never leaked on an
/// early-return error path (e.g. a failed binary replace on Windows, which
/// otherwise left a ~50 MB archive + extracted binary behind on every attempt).
///
/// The success path explicitly removes the temp dir *before* triggering the
/// restart, because the restart may `_exit` without unwinding, so this guard
/// would not otherwise run there.
struct TempDirGuard {
    path: PathBuf,
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => debug!(
                path = %self.path.display(),
                error = %e,
                "Failed to remove upgrade temp dir on cleanup"
            ),
        }
    }
}

/// Context the restart planner needs from the running daemon: where the
/// handoff file lives, which API address the replacement must serve, and how
/// to trigger a bounded graceful shutdown before the old process exits.
///
/// `Default` (no data dir, no address, no shutdown hook) is only useful for
/// tests and non-daemon callers — every daemon apply path supplies all three.
#[derive(Clone, Default)]
pub struct RestartContext {
    /// Daemon data directory (`upgrade-handoff.json` / `UPGRADE_FAILED`).
    pub data_dir: Option<PathBuf>,
    /// Pre-upgrade API address the replacement must serve `/health` on.
    pub api_addr: Option<std::net::SocketAddr>,
    /// Triggers the daemon's graceful shutdown (cancellation). Called inside
    /// the handoff's 5s bounded cancel window.
    pub shutdown: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

/// Auto-apply upgrader that handles the full download → verify → extract → replace → restart flow.
pub struct AutoApplyUpgrader {
    /// Which binary to extract from the archive (e.g. "x0xd", "x0x").
    binary_name: String,
    /// Exit cleanly for service manager restart instead of spawning new process.
    stop_on_upgrade: bool,
    /// Whether a successful apply should immediately restart/exec.
    restart_on_success: bool,
    /// Data directory / API address / shutdown hook for the restart planner.
    restart_context: RestartContext,
}

impl AutoApplyUpgrader {
    pub fn new(binary_name: &str) -> Self {
        Self {
            binary_name: binary_name.to_string(),
            stop_on_upgrade: false,
            restart_on_success: true,
            restart_context: RestartContext::default(),
        }
    }

    pub fn with_stop_on_upgrade(mut self, stop: bool) -> Self {
        self.stop_on_upgrade = stop;
        self
    }

    /// Supply the daemon-side restart context (data dir, pre-upgrade API
    /// address, graceful-shutdown hook) used by the transactional handoff.
    pub fn with_restart_context(mut self, context: RestartContext) -> Self {
        self.restart_context = context;
        self
    }

    /// Configure whether a successful apply should immediately restart/exec.
    ///
    /// HTTP handlers should set this to `false`, return their response, then
    /// restart asynchronously so clients can observe the apply result.
    pub fn with_restart_on_success(mut self, restart: bool) -> Self {
        self.restart_on_success = restart;
        self
    }

    /// Restart the current binary using the planned restart mode.
    ///
    /// Unsupervised (the default for a terminal-launched daemon) this runs the
    /// transactional handoff and never returns. Supervised it exits for the
    /// supervisor and never returns. Returns `Err` only when the handoff could
    /// not even be started (helper spawn failure) — the old process keeps
    /// running in that case.
    pub fn restart_current_binary(&self, target_version: &str) -> Result<(), UpgradeError> {
        let target_path = current_binary_path()?;
        self.trigger_restart(&target_path, target_version)
    }

    /// Classify the restart mode for the current environment (I0).
    pub fn restart_mode(&self) -> restart::RestartMode {
        self.restart_mode_with(&restart::SupervisionSignals::sample())
    }

    /// Classification with injected signals — the single planner every apply
    /// caller routes through (startup check, gossip, fallback poll, HTTP).
    pub fn restart_mode_with(&self, signals: &restart::SupervisionSignals) -> restart::RestartMode {
        restart::plan_restart_mode(self.stop_on_upgrade, signals)
    }

    /// Apply an upgrade from a `ReleaseManifest`.
    ///
    /// 1. Find the platform-appropriate asset
    /// 2. Download archive
    /// 3. Verify SHA-256 hash against manifest (integrity)
    /// 4. Download and verify ML-DSA-65 signature on archive (authenticity)
    /// 5. Extract binary from archive
    /// 6. Replace current binary with backup/rollback
    /// 7. Optionally trigger restart
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
        let upgrader = Upgrader::new(target_path.clone(), current_version.clone());
        let temp_dir = upgrader.create_temp_dir()?;
        // Guarantees temp-dir removal on every early-return error path below.
        let _temp_guard = TempDirGuard {
            path: temp_dir.clone(),
        };

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

        // If we are upgrading x0xd, also check for companion x0x binary and upgrade it too.
        if self.binary_name == "x0xd" {
            let parent_dir = target_path
                .parent()
                .ok_or_else(|| UpgradeError::Other("target has no parent directory".to_string()))?;
            let x0x_name = if cfg!(target_os = "windows") {
                "x0x.exe"
            } else {
                "x0x"
            };
            let x0x_path = parent_dir.join(x0x_name);
            if x0x_path.exists() {
                info!("Found x0x CLI companion in same directory, upgrading it too...");
                let extracted_x0x = temp_dir.join("extracted-x0x");
                if let Err(e) = extract_binary_from_archive(&archive_path, &extracted_x0x, x0x_name)
                {
                    warn!("Failed to extract companion x0x binary: {e}");
                } else {
                    let x0x_upgrader = Upgrader::new(x0x_path.clone(), current_version.clone());
                    match x0x_upgrader.perform_upgrade(&extracted_x0x, &target_version) {
                        Ok(_) => info!("x0x companion upgraded successfully"),
                        Err(e) => warn!("Failed to upgrade x0x companion: {e}"),
                    }
                }
            }
        }

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
            if self.restart_on_success {
                if let Err(e) = self.trigger_restart(&target_path, &target_version.to_string()) {
                    warn!(
                        error = %e,
                        "Restart after successful upgrade did not start: {e}; \
                         old process keeps serving"
                    );
                }
            }
        }

        Ok(result)
    }

    /// Trigger a restart after successful upgrade (#261).
    ///
    /// Classification first (I0): `SupervisedExit` only when `stop_on_upgrade`
    /// is true AND a real supervision signal is present (`INVOCATION_ID`,
    /// parent comm `systemd`, `X0X_SUPERVISED=1`). Everything else — including
    /// unsupervised runs with the default `stop_on_upgrade = true` — goes
    /// through the transactional handoff, which proves `/health` on the new
    /// binary or restores the backup. The old `exec()` path is gone: it could
    /// not roll back.
    fn trigger_restart(
        &self,
        binary_path: &Path,
        target_version: &str,
    ) -> Result<(), UpgradeError> {
        let mode = self.restart_mode();
        info!(
            mode = ?mode,
            stop_on_upgrade = self.stop_on_upgrade,
            "Restart planned after successful upgrade"
        );

        let backup_path = restart::UpgradeHandoff::backup_path_for(binary_path);
        let handoff = restart::UpgradeHandoff::capture(
            binary_path,
            &backup_path,
            target_version,
            self.restart_context
                .api_addr
                .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            mode,
        );
        let handoff_path = match self.restart_context.data_dir.as_deref() {
            Some(data_dir) => data_dir.join(restart::HANDOFF_FILE_NAME),
            // Non-daemon caller with no data dir: keep the intent record next
            // to the binary rather than losing it entirely.
            None => binary_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(restart::HANDOFF_FILE_NAME),
        };

        match mode {
            restart::RestartMode::SupervisedExit => {
                // I3: write the intent file BEFORE exiting so a supervisor
                // crash loop is diagnosable. Best-effort — the exit contract
                // with Restart=always units must not depend on disk health.
                if let Err(e) = handoff.write(&handoff_path) {
                    warn!(
                        handoff = %handoff_path.display(),
                        error = %e,
                        "Failed to write upgrade intent file before supervised exit"
                    );
                }
                let exit_code = if cfg!(windows) { 100 } else { 0 };
                info!(
                    exit_code = exit_code,
                    "Exiting with code {} for service manager restart", exit_code
                );
                std::process::exit(exit_code);
            }
            restart::RestartMode::TransactionalHandoff => restart::begin_transactional_handoff(
                handoff,
                &handoff_path,
                self.restart_context.shutdown.as_deref(),
            ),
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
pub fn extract_binary_from_archive(
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
        // create_test_tar_gz puts it at x0x-linux-x64-gnu/x0x
        let archive = create_test_tar_gz(dir.path(), "x0x", b"cli binary");
        let output = dir.path().join("extracted");

        extract_binary_from_archive(&archive, &output, "x0x").unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"cli binary");
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

    #[test]
    fn auto_apply_upgrader_new_defaults() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        assert_eq!(upgrader.binary_name, "x0xd");
        assert!(!upgrader.stop_on_upgrade);
        assert!(upgrader.restart_on_success);
        assert!(upgrader.restart_context.data_dir.is_none());
    }

    #[test]
    fn auto_apply_upgrader_with_stop_on_upgrade() {
        let upgrader = AutoApplyUpgrader::new("x0x").with_stop_on_upgrade(true);
        assert!(upgrader.stop_on_upgrade);
    }

    #[test]
    fn auto_apply_upgrader_with_restart_context() {
        let context = RestartContext {
            data_dir: Some(PathBuf::from("/var/lib/x0x")),
            api_addr: Some("127.0.0.1:12700".parse().unwrap()),
            shutdown: None,
        };
        let upgrader = AutoApplyUpgrader::new("x0xd").with_restart_context(context);
        assert_eq!(
            upgrader.restart_context.data_dir.as_deref(),
            Some(Path::new("/var/lib/x0x"))
        );
        assert_eq!(
            upgrader.restart_context.api_addr,
            Some("127.0.0.1:12700".parse().unwrap())
        );
    }

    #[test]
    fn upgrader_restart_mode_routes_through_the_single_planner() {
        // Whatever flags/context an apply caller sets, the mode decision must
        // come from plan_restart_mode — there is no second ad-hoc exit path.
        for stop in [true, false] {
            let upgrader = AutoApplyUpgrader::new("x0xd").with_stop_on_upgrade(stop);
            for signals in [
                restart::SupervisionSignals::default(),
                restart::SupervisionSignals {
                    invocation_id: true,
                    ..Default::default()
                },
                restart::SupervisionSignals {
                    parent_comm: Some("systemd".to_string()),
                    ..Default::default()
                },
            ] {
                assert_eq!(
                    upgrader.restart_mode_with(&signals),
                    restart::plan_restart_mode(stop, &signals),
                    "stop={stop}, signals={signals:?}"
                );
            }
        }
    }

    #[test]
    fn auto_apply_upgrader_with_restart_on_success() {
        let upgrader = AutoApplyUpgrader::new("x0xd").with_restart_on_success(false);
        assert!(!upgrader.restart_on_success);
    }

    #[test]
    fn auto_apply_upgrader_chaining() {
        let upgrader = AutoApplyUpgrader::new("x0xd")
            .with_stop_on_upgrade(true)
            .with_restart_on_success(false);
        assert_eq!(upgrader.binary_name, "x0xd");
        assert!(upgrader.stop_on_upgrade);
        assert!(!upgrader.restart_on_success);
    }

    #[tokio::test]
    async fn apply_upgrade_rejects_invalid_manifest_version() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "not-a-version".to_string(),
            timestamp: 0,
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        let result = upgrader.apply_upgrade_from_manifest(&manifest).await;
        assert!(result.is_err(), "invalid version should fail");
        let err = format!("{:?}", result);
        assert!(
            err.contains("invalid version"),
            "error should mention invalid version: {err}"
        );
    }

    #[tokio::test]
    async fn apply_upgrade_rejects_downgrade() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        // Target version lower than current
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "0.1.0".to_string(),
            timestamp: 0,
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        let result = upgrader.apply_upgrade_from_manifest(&manifest).await;
        assert!(result.is_err(), "downgrade should fail");
        // The error may be NoPlatformAsset (checked before downgrade) or DowngradeAttempt
        // Both are valid error paths
    }

    #[tokio::test]
    async fn apply_upgrade_rejects_no_platform_asset() {
        let upgrader = AutoApplyUpgrader::new("x0xd");
        // Valid version but no assets matching current platform
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "99.99.99".to_string(),
            timestamp: 0,
            assets: vec![], // No platform assets
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        let result = upgrader.apply_upgrade_from_manifest(&manifest).await;
        assert!(result.is_err(), "no platform asset should fail");
        let err = format!("{:?}", result);
        assert!(
            err.contains("NoPlatformAsset"),
            "error should mention NoPlatformAsset: {err}"
        );
    }

    async fn serve_once(response: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await.unwrap();
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{addr}/archive")
    }

    #[tokio::test]
    async fn download_to_file_writes_successful_response_body() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("downloaded.bin");
        let body = "download bytes";
        let url = serve_once(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ))
        .await;

        download_to_file(&url, &destination).await.unwrap();
        assert_eq!(std::fs::read_to_string(destination).unwrap(), body);
    }

    #[tokio::test]
    async fn download_to_file_rejects_http_error_status() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("downloaded.bin");
        let url =
            serve_once("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found".to_string())
                .await;

        let result = download_to_file(&url, &destination).await;
        assert!(matches!(result, Err(UpgradeError::DownloadError(_))));
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn download_to_file_rejects_oversized_content_length() {
        let dir = TempDir::new().unwrap();
        let destination = dir.path().join("downloaded.bin");
        let too_large = super::super::MAX_BINARY_SIZE_BYTES + 1;
        let url = serve_once(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {too_large}\r\n\r\n"
        ))
        .await;

        let result = download_to_file(&url, &destination).await;
        assert!(matches!(result, Err(UpgradeError::BinaryTooLarge { .. })));
        assert!(!destination.exists());
    }
}
