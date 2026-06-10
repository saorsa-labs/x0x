//! Standalone upgrade command — works without a running daemon.
//!
//! Checks GitHub for updates, downloads the release archive, verifies
//! the ML-DSA-65 signature and SHA-256 hash, then replaces both `x0x`
//! and `x0xd` binaries in place.

use anyhow::{Context, Result};
use semver::Version;

use crate::upgrade::apply::current_binary_path;
use crate::upgrade::monitor::UpgradeMonitor;
use crate::upgrade::UpgradeError;

const REPO: &str = "saorsa-labs/x0x";

/// `x0x upgrade` — standalone upgrade (no daemon required).
pub async fn run(check_only: bool, force: bool) -> Result<()> {
    let current = crate::VERSION;
    eprintln!("x0x v{current}");
    eprintln!("Checking for updates...");

    let monitor = UpgradeMonitor::new(REPO, "x0x", current)
        .map_err(|e| anyhow::anyhow!("failed to create upgrade monitor: {e}"))?;

    // If --force, we fetch the current manifest regardless of version comparison.
    let verified = if force {
        match monitor.fetch_current_manifest().await {
            Ok(v) => v,
            Err(e) => {
                print_signature_recovery_hint(&e, current);
                return Err(anyhow::anyhow!("failed to fetch release from GitHub: {e}"));
            }
        }
    } else {
        match monitor.check_for_updates().await {
            Ok(Some(v)) => Some(v),
            Ok(None) => {
                eprintln!("Already on the latest version (v{current}).");
                return Ok(());
            }
            Err(e) => {
                print_signature_recovery_hint(&e, current);
                return Err(anyhow::anyhow!("failed to check for updates: {e}"));
            }
        }
    };

    let verified = match verified {
        Some(v) => v,
        None => {
            eprintln!("No release found on GitHub.");
            return Ok(());
        }
    };

    let new_version = &verified.manifest.version;

    if check_only {
        eprintln!("Update available: v{current} → v{new_version}");
        eprintln!("Run `x0x upgrade` to install.");
        return Ok(());
    }

    if force {
        eprintln!("Force installing v{new_version}...");
    } else {
        eprintln!("Upgrading v{current} → v{new_version}...");
    }

    // Upgrade x0xd first (the daemon binary)
    let x0x_path = current_binary_path().context("cannot resolve x0x binary path")?;
    let bin_dir = x0x_path
        .parent()
        .context("x0x binary has no parent directory")?;

    let x0xd_path = bin_dir.join(if cfg!(windows) { "x0xd.exe" } else { "x0xd" });

    // Check if x0xd exists in the same directory
    let has_x0xd = x0xd_path.exists();

    // Stop the daemon if it's running (can't replace binary while it's in use)
    let daemon_was_running = stop_daemon_if_running().await;
    if daemon_was_running {
        eprintln!("Stopped running daemon.");
    }

    if has_x0xd {
        eprintln!("Upgrading x0xd...");
        upgrade_binary("x0xd", &verified.manifest, force).await?;
        eprintln!("  x0xd → v{new_version}");
    }

    eprintln!("Upgrading x0x...");
    upgrade_binary("x0x", &verified.manifest, force).await?;
    eprintln!("  x0x  → v{new_version}");

    // Clean up stale x0x-bootstrap if present (removed in v0.8.0)
    let bootstrap_path = bin_dir.join(if cfg!(windows) {
        "x0x-bootstrap.exe"
    } else {
        "x0x-bootstrap"
    });
    if bootstrap_path.exists() {
        let _ = std::fs::remove_file(&bootstrap_path);
        eprintln!("  Removed stale x0x-bootstrap (no longer needed since v0.8.0)");
    }

    eprintln!();
    eprintln!("Upgrade complete: v{new_version}");

    // Restart the daemon if it was running before
    if daemon_was_running {
        eprintln!("Restarting daemon...");
        if let Err(e) = restart_daemon().await {
            eprintln!("  Failed to restart daemon: {e}");
            eprintln!("  Start manually: x0x start");
        } else {
            eprintln!("  Daemon restarted.");
        }
    }

    Ok(())
}

/// Upgrade a single binary using the release manifest.
///
/// Uses `AutoApplyUpgrader` without trigger_restart — the CLI handles
/// restart messaging itself.
async fn upgrade_binary(
    binary_name: &str,
    manifest: &crate::upgrade::manifest::ReleaseManifest,
    force: bool,
) -> Result<()> {
    let target_version = Version::parse(&manifest.version)
        .map_err(|e| anyhow::anyhow!("invalid version in manifest: {e}"))?;
    let current_version = Version::parse(crate::VERSION)
        .map_err(|e| anyhow::anyhow!("invalid current version: {e}"))?;

    // For --force, skip the version check by using a custom flow
    // instead of AutoApplyUpgrader (which calls trigger_restart and validate_upgrade).
    upgrade_binary_manual(
        binary_name,
        manifest,
        &current_version,
        &target_version,
        force,
    )
    .await
}

/// Manual upgrade flow that skips trigger_restart and optionally skips version check.
async fn upgrade_binary_manual(
    binary_name: &str,
    manifest: &crate::upgrade::manifest::ReleaseManifest,
    current_version: &Version,
    target_version: &Version,
    force: bool,
) -> Result<()> {
    use crate::upgrade::manifest::current_platform_target;
    use crate::upgrade::signature::{verify_bytes_signature_with_key, RELEASE_SIGNING_KEY};
    use crate::upgrade::Upgrader;
    use sha2::{Digest, Sha256};

    let platform_target = current_platform_target().context("unsupported platform for upgrade")?;

    let asset = manifest
        .matches_platform(platform_target)
        .context("no release asset for this platform")?;

    // Resolve the binary path — for "x0x" use current_exe, for others look in same dir
    let target_path = if binary_name == "x0x" {
        current_binary_path().context("cannot resolve binary path")?
    } else {
        let x0x_path = current_binary_path().context("cannot resolve x0x path")?;
        let dir = x0x_path
            .parent()
            .context("binary has no parent directory")?;
        let name = if cfg!(windows) && !binary_name.ends_with(".exe") {
            format!("{binary_name}.exe")
        } else {
            binary_name.to_string()
        };
        dir.join(name)
    };

    if !target_path.exists() {
        anyhow::bail!("{binary_name} not found at {}", target_path.display());
    }

    let upgrader = if force {
        // For --force, use version 0.0.0 so validate_upgrade always passes
        Upgrader::new(target_path.clone(), Version::new(0, 0, 0))
    } else {
        Upgrader::new(target_path.clone(), current_version.clone())
    };

    let temp_dir = upgrader
        .create_temp_dir()
        .context("failed to create temp directory")?;

    let archive_path = temp_dir.join("archive");
    let sig_path = temp_dir.join("archive.sig");

    // Download archive
    download_to_file(&asset.archive_url, &archive_path).await?;

    let archive_data = std::fs::read(&archive_path).context("failed to read downloaded archive")?;

    // Verify SHA-256
    let actual_hash: [u8; 32] = Sha256::digest(&archive_data).into();
    if actual_hash != asset.archive_sha256 {
        let _ = std::fs::remove_dir_all(&temp_dir);
        anyhow::bail!(
            "SHA-256 mismatch: expected {}, got {}",
            hex::encode(asset.archive_sha256),
            hex::encode(actual_hash)
        );
    }

    // Download and verify ML-DSA-65 signature
    download_to_file(&asset.signature_url, &sig_path).await?;
    let sig_data = std::fs::read(&sig_path).context("failed to read signature")?;

    verify_bytes_signature_with_key(&archive_data, &sig_data, RELEASE_SIGNING_KEY)
        .context("archive signature verification failed")?;

    // Extract binary
    let binary_filename = if cfg!(target_os = "windows") && !binary_name.ends_with(".exe") {
        format!("{binary_name}.exe")
    } else {
        binary_name.to_string()
    };
    let extracted_path = temp_dir.join("extracted-binary");
    crate::upgrade::apply::extract_binary_from_archive(
        &archive_path,
        &extracted_path,
        &binary_filename,
    )
    .context("failed to extract binary from archive")?;

    // Replace binary (with backup + rollback)
    upgrader
        .perform_upgrade(&extracted_path, target_version)
        .context("failed to replace binary")?;

    // Clean up temp dir
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(())
}

/// Discover the daemon API address from the port file, if running.
fn discover_daemon_api() -> Option<String> {
    discover_daemon_api_in(&dirs::data_dir()?)
}

/// Discover the daemon API address from `<data_dir>/x0x/api.port`.
fn discover_daemon_api_in(data_dir: &std::path::Path) -> Option<String> {
    let port_file = data_dir.join("x0x").join("api.port");
    std::fs::read_to_string(port_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Stop the daemon if it's running. Returns true if it was running.
async fn stop_daemon_if_running() -> bool {
    match dirs::data_dir() {
        Some(data_dir) => stop_daemon_if_running_in(&data_dir).await,
        None => false,
    }
}

/// Stop the daemon whose port file lives under `data_dir`, if it's running.
async fn stop_daemon_if_running_in(data_dir: &std::path::Path) -> bool {
    let addr = match discover_daemon_api_in(data_dir) {
        Some(a) => a,
        None => return false,
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Check if daemon is actually responding
    let health_url = format!("http://{addr}/health");
    if client.get(&health_url).send().await.is_err() {
        return false;
    }

    // Read the API token for authenticated shutdown
    let token = read_api_token_in(data_dir);

    // Send shutdown
    let shutdown_url = format!("http://{addr}/shutdown");
    let mut req = client.post(&shutdown_url);
    if let Some(ref t) = token {
        req = req.bearer_auth(t);
    }
    let _ = req.send().await;

    // Wait for daemon to actually stop (up to 5 seconds)
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if client.get(&health_url).send().await.is_err() {
            return true;
        }
    }

    true
}

/// Read the API token from `<data_dir>/x0x/api.token`.
fn read_api_token_in(data_dir: &std::path::Path) -> Option<String> {
    let token_file = data_dir.join("x0x").join("api.token");
    std::fs::read_to_string(token_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Restart the daemon after upgrade.
async fn restart_daemon() -> Result<()> {
    let x0x_path = current_binary_path().context("cannot resolve x0x binary path")?;
    let bin_dir = x0x_path
        .parent()
        .context("x0x binary has no parent directory")?;

    let x0xd_name = if cfg!(windows) { "x0xd.exe" } else { "x0xd" };
    let x0xd_path = bin_dir.join(x0xd_name);

    if !x0xd_path.exists() {
        anyhow::bail!("x0xd not found at {}", x0xd_path.display());
    }

    // Start x0xd as a background process (same as `x0x start`)
    let data_dir = dirs::data_dir().context("cannot determine data directory")?;
    let log_dir = data_dir.join("x0x");
    std::fs::create_dir_all(&log_dir).ok();
    let log_file = log_dir.join("x0xd.log");

    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
        .context("failed to open log file")?;

    std::process::Command::new(&x0xd_path)
        .arg("--skip-update-check")
        .stdout(log.try_clone().context("failed to clone log handle")?)
        .stderr(log)
        .spawn()
        .context("failed to spawn x0xd")?;

    // Wait for it to become healthy (up to 15 seconds)
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client")?;

    for _ in 0..15 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Some(addr) = discover_daemon_api() {
            let url = format!("http://{addr}/health");
            if client.get(&url).send().await.is_ok() {
                return Ok(());
            }
        }
    }

    anyhow::bail!("daemon started but did not become healthy within 15 seconds")
}

/// Download a URL to a local file (reuses the same logic as apply.rs).
async fn download_to_file(url: &str, destination: &std::path::Path) -> Result<()> {
    use crate::upgrade::MAX_BINARY_SIZE_BYTES;
    use futures::StreamExt;
    use std::io::Write;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("failed to build HTTP client")?;

    let response = client
        .get(url)
        .send()
        .await
        .context("download failed")?
        .error_for_status()
        .context("download returned error status")?;

    if let Some(content_length) = response.content_length() {
        if content_length > MAX_BINARY_SIZE_BYTES {
            anyhow::bail!(
                "binary too large: {} bytes (limit: {} bytes)",
                content_length,
                MAX_BINARY_SIZE_BYTES
            );
        }
    }

    let mut file = std::fs::File::create(destination).context("failed to create download file")?;
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.context("download stream error")?;
        downloaded += chunk.len() as u64;
        if downloaded > MAX_BINARY_SIZE_BYTES {
            drop(file);
            let _ = std::fs::remove_file(destination);
            anyhow::bail!(
                "binary too large: {} bytes (limit: {} bytes)",
                downloaded,
                MAX_BINARY_SIZE_BYTES
            );
        }
        file.write_all(&chunk).context("failed to write chunk")?;
    }

    Ok(())
}

/// If the error is a signature verification failure, print recovery instructions
/// so users on older builds with a mismatched signing key can still upgrade.
fn print_signature_recovery_hint(err: &UpgradeError, current: &str) {
    if !matches!(err, UpgradeError::ManifestSignatureInvalid) {
        return;
    }
    eprintln!();
    eprintln!("The release signature could not be verified with this binary's");
    eprintln!("embedded signing key. This typically means your x0x installation");
    eprintln!("(v{current}) predates a signing key update.");
    eprintln!();
    eprintln!("To update manually, run:");
    eprintln!();
    eprintln!("  curl -sfL https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh | sh");
    eprintln!();
    eprintln!("Or install via cargo:");
    eprintln!();
    eprintln!("  cargo install x0x --force");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upgrade::UpgradeError;

    async fn start_download_server(
        status: u16,
        body: &'static [u8],
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        let app = axum::Router::new().fallback(move |_req: axum::extract::Request| async move {
            axum::response::Response::builder()
                .status(status)
                .body(axum::body::Body::from(body))
                .expect("response should build")
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("read listener addr");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
                .ok();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (format!("http://{}", addr), tx)
    }

    #[test]
    fn print_signature_recovery_hint_prints_for_signature_error() {
        // Should not panic
        print_signature_recovery_hint(&UpgradeError::ManifestSignatureInvalid, "0.19.42");
    }

    #[test]
    fn print_signature_recovery_hint_skips_for_other_errors() {
        // Should not panic for non-signature errors
        print_signature_recovery_hint(
            &UpgradeError::ManifestFetchFailed("network error".to_string()),
            "0.19.42",
        );
    }

    #[test]
    fn discover_daemon_api_returns_none_without_port_file() {
        // An isolated data dir with no port file means no daemon to talk to
        let dir = tempfile::tempdir().expect("temp dir");
        let result = discover_daemon_api_in(dir.path());
        assert!(
            result.is_none(),
            "should return None without a running daemon"
        );
    }

    #[test]
    fn discover_daemon_api_reads_trimmed_port_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let x0x_dir = dir.path().join("x0x");
        std::fs::create_dir_all(&x0x_dir).expect("create x0x dir");
        std::fs::write(x0x_dir.join("api.port"), "127.0.0.1:12700\n").expect("write port file");

        let result = discover_daemon_api_in(dir.path());
        assert_eq!(result.as_deref(), Some("127.0.0.1:12700"));
    }

    #[test]
    fn read_api_token_returns_none_without_token_file() {
        // An isolated data dir with no token file means no configured token
        let dir = tempfile::tempdir().expect("temp dir");
        let result = read_api_token_in(dir.path());
        assert!(
            result.is_none(),
            "should return None without a configured token"
        );
    }

    #[test]
    fn read_api_token_ignores_empty_token_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let x0x_dir = dir.path().join("x0x");
        std::fs::create_dir_all(&x0x_dir).expect("create x0x dir");
        std::fs::write(x0x_dir.join("api.token"), "  \n").expect("write token file");

        let result = read_api_token_in(dir.path());
        assert!(result.is_none(), "whitespace-only token must be ignored");
    }

    #[tokio::test]
    async fn download_to_file_writes_successful_response() {
        let (url, _shutdown) = start_download_server(200, b"archive-bytes").await;
        let dir = tempfile::tempdir().expect("temp dir");
        let destination = dir.path().join("archive");

        download_to_file(&url, &destination)
            .await
            .expect("download should succeed");

        let bytes = std::fs::read(destination).expect("read downloaded file");
        assert_eq!(bytes, b"archive-bytes");
    }

    #[tokio::test]
    async fn download_to_file_reports_http_error_status() {
        let (url, _shutdown) = start_download_server(503, b"unavailable").await;
        let dir = tempfile::tempdir().expect("temp dir");
        let destination = dir.path().join("archive");

        let result = download_to_file(&url, &destination).await;

        assert!(result.is_err());
        assert!(result
            .expect_err("download should fail")
            .to_string()
            .contains("download returned error status"));
    }

    #[tokio::test]
    async fn stop_daemon_if_running_returns_false_without_port_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(!stop_daemon_if_running_in(dir.path()).await);
    }
}
