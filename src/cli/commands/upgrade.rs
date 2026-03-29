//! Standalone upgrade command — works without a running daemon.
//!
//! Checks GitHub for updates, downloads the release archive, verifies
//! the ML-DSA-65 signature and SHA-256 hash, then replaces both `x0x`
//! and `x0xd` binaries in place.

use anyhow::{Context, Result};
use semver::Version;

use crate::upgrade::apply::current_binary_path;
use crate::upgrade::monitor::UpgradeMonitor;

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
        monitor
            .fetch_current_manifest()
            .await
            .context("failed to fetch release from GitHub")?
    } else {
        match monitor
            .check_for_updates()
            .await
            .context("failed to check for updates")?
        {
            Some(v) => Some(v),
            None => {
                eprintln!("Already on the latest version (v{current}).");
                return Ok(());
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

    // If x0xd was running, tell the user to restart it
    if has_x0xd {
        eprintln!("Restart the daemon: x0x stop && x0x start");
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
