use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use super::notification::{PlatformAsset, ReleaseNotification};
use super::UpgradeInfo;

/// GitHub API release response.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub body: Option<String>,
    pub assets: Vec<GitHubAsset>,
}

/// GitHub API asset response.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
}

/// Monitors GitHub releases for updates.
///
/// Primary update mechanism for x0x-bootstrap (6h poll).
/// Fallback mechanism for x0xd (startup check + 48h poll).
pub struct UpgradeMonitor {
    repo: String,
    binary_name: String,
    current_version: Version,
    client: Client,
    include_prereleases: bool,
}

impl UpgradeMonitor {
    /// Create a new upgrade monitor.
    ///
    /// # Arguments
    /// * `repo` - GitHub repo in "owner/repo" format (e.g. "saorsa-labs/x0x")
    /// * `binary_name` - Name of the binary to extract from archives ("x0xd" or "x0x-bootstrap")
    /// * `current_version` - The currently running version string
    pub fn new(repo: &str, binary_name: &str, current_version: &str) -> Result<Self, String> {
        let version =
            Version::parse(current_version).map_err(|e| format!("invalid version: {e}"))?;

        let client = Client::builder()
            .user_agent(format!("{binary_name}/{current_version}"))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        Ok(Self {
            repo: repo.to_string(),
            binary_name: binary_name.to_string(),
            current_version: version,
            client,
            include_prereleases: false,
        })
    }

    /// Enable or disable inclusion of pre-releases in update checks.
    pub fn with_include_prereleases(mut self, include: bool) -> Self {
        self.include_prereleases = include;
        self
    }

    /// Check GitHub for a newer release.
    ///
    /// Returns `Some(UpgradeInfo)` if a newer version is available, `None` otherwise.
    /// When `include_prereleases` is true, fetches all releases and considers pre-releases.
    pub async fn check_for_updates(&self) -> Result<Option<UpgradeInfo>, String> {
        let release = if self.include_prereleases {
            self.fetch_latest_release_including_prereleases().await?
        } else {
            let api_url = format!("https://api.github.com/repos/{}/releases/latest", self.repo);
            debug!("Checking for updates from: {}", api_url);
            self.client
                .get(&api_url)
                .send()
                .await
                .map_err(|e| format!("GitHub API request failed: {e}"))?
                .error_for_status()
                .map_err(|e| format!("GitHub API error: {e}"))?
                .json::<GitHubRelease>()
                .await
                .map_err(|e| format!("Failed to parse GitHub release: {e}"))?
        };

        let latest_version_str = version_from_tag(&release.tag_name);
        let latest_version = Version::parse(latest_version_str)
            .map_err(|e| format!("Invalid version in tag '{}': {e}", release.tag_name))?;

        if latest_version <= self.current_version {
            debug!(
                current_version = %self.current_version,
                "Current version {} is up to date",
                self.current_version
            );
            return Ok(None);
        }

        info!(
            current_version = %self.current_version,
            new_version = %latest_version,
            "New version available"
        );

        let platform_target = super::notification::current_platform_target()
            .ok_or_else(|| "unsupported platform".to_string())?;

        let (archive_url, signature_url) =
            find_platform_asset(&release, platform_target, &self.binary_name)?;

        Ok(Some(UpgradeInfo {
            version: latest_version.to_string(),
            download_url: archive_url,
            signature_url,
            release_notes: release.body,
        }))
    }

    /// Build a `ReleaseNotification` from a GitHub release, for gossip broadcasting.
    ///
    /// Called by x0x-bootstrap after a successful self-upgrade.
    pub async fn build_release_notification(
        &self,
        release: &GitHubRelease,
    ) -> Result<ReleaseNotification, String> {
        let version = version_from_tag(&release.tag_name).to_string();

        let mut assets = Vec::new();
        let platform_targets = [
            ("x86_64-unknown-linux-gnu", "x0x-linux-x64-gnu"),
            ("aarch64-unknown-linux-gnu", "x0x-linux-arm64-gnu"),
            ("x86_64-apple-darwin", "x0x-macos-x64"),
            ("aarch64-apple-darwin", "x0x-macos-arm64"),
            ("x86_64-pc-windows-msvc", "x0x-windows-x64"),
        ];

        for (target, archive_prefix) in &platform_targets {
            let archive_ext = if target.contains("windows") {
                "zip"
            } else {
                "tar.gz"
            };
            let archive_name = format!("{archive_prefix}.{archive_ext}");
            let sig_name = format!("{archive_name}.sig");

            if let (Some(archive_asset), Some(sig_asset)) = (
                release.assets.iter().find(|a| a.name == archive_name),
                release.assets.iter().find(|a| a.name == sig_name),
            ) {
                assets.push(PlatformAsset {
                    target: target.to_string(),
                    archive_url: archive_asset.browser_download_url.clone(),
                    signature_url: sig_asset.browser_download_url.clone(),
                });
            }
        }

        // Fetch SKILL.md hash
        let (skill_sha256, skill_url) = self.fetch_skill_info(&release.assets).await;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(ReleaseNotification {
            version,
            assets,
            skill_sha256,
            skill_url,
            timestamp,
        })
    }

    /// Fetch the latest GitHub release metadata (for building notifications).
    /// Respects the `include_prereleases` flag.
    pub async fn fetch_latest_release(&self) -> Result<GitHubRelease, String> {
        if self.include_prereleases {
            self.fetch_latest_release_including_prereleases().await
        } else {
            let api_url = format!("https://api.github.com/repos/{}/releases/latest", self.repo);
            self.client
                .get(&api_url)
                .send()
                .await
                .map_err(|e| format!("GitHub API request failed: {e}"))?
                .error_for_status()
                .map_err(|e| format!("GitHub API error: {e}"))?
                .json::<GitHubRelease>()
                .await
                .map_err(|e| format!("Failed to parse GitHub release: {e}"))
        }
    }

    /// Fetch the latest release including pre-releases by listing all releases
    /// and returning the first one (which GitHub returns sorted newest-first).
    async fn fetch_latest_release_including_prereleases(&self) -> Result<GitHubRelease, String> {
        let api_url = format!(
            "https://api.github.com/repos/{}/releases?per_page=1",
            self.repo
        );
        debug!(
            "Checking for updates (including prereleases) from: {}",
            api_url
        );

        let releases: Vec<GitHubRelease> = self
            .client
            .get(&api_url)
            .send()
            .await
            .map_err(|e| format!("GitHub API request failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("GitHub API error: {e}"))?
            .json()
            .await
            .map_err(|e| format!("Failed to parse GitHub releases: {e}"))?;

        releases
            .into_iter()
            .next()
            .ok_or_else(|| "no releases found".to_string())
    }

    /// Look up SKILL.md in the release assets, download it, and compute its SHA-256.
    async fn fetch_skill_info(&self, assets: &[GitHubAsset]) -> ([u8; 32], String) {
        let skill_asset = assets.iter().find(|a| a.name == "SKILL.md");
        match skill_asset {
            Some(asset) => {
                let url = asset.browser_download_url.clone();
                match self.client.get(&url).send().await {
                    Ok(resp) => match resp.bytes().await {
                        Ok(bytes) => {
                            let hash: [u8; 32] = Sha256::digest(&bytes).into();
                            (hash, url)
                        }
                        Err(_) => ([0u8; 32], url),
                    },
                    Err(_) => ([0u8; 32], url),
                }
            }
            None => ([0u8; 32], String::new()),
        }
    }
}

/// Strip the `v` prefix from a git tag to get the semver version.
pub fn version_from_tag(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Find the platform-appropriate archive and signature URLs from a release.
fn find_platform_asset(
    release: &GitHubRelease,
    platform_target: &str,
    _binary_name: &str,
) -> Result<(String, String), String> {
    let (archive_prefix, archive_ext) = match platform_target {
        "x86_64-unknown-linux-gnu" => ("x0x-linux-x64-gnu", "tar.gz"),
        "aarch64-unknown-linux-gnu" => ("x0x-linux-arm64-gnu", "tar.gz"),
        "x86_64-apple-darwin" => ("x0x-macos-x64", "tar.gz"),
        "aarch64-apple-darwin" => ("x0x-macos-arm64", "tar.gz"),
        "x86_64-pc-windows-msvc" => ("x0x-windows-x64", "zip"),
        other => return Err(format!("unsupported platform: {other}")),
    };

    let archive_name = format!("{archive_prefix}.{archive_ext}");
    let sig_name = format!("{archive_name}.sig");

    let archive_url = release
        .assets
        .iter()
        .find(|a| a.name == archive_name)
        .map(|a| a.browser_download_url.clone())
        .ok_or_else(|| format!("release missing archive: {archive_name}"))?;

    let sig_url = release
        .assets
        .iter()
        .find(|a| a.name == sig_name)
        .map(|a| a.browser_download_url.clone())
        .ok_or_else(|| format!("release missing signature: {sig_name}"))?;

    Ok((archive_url, sig_url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_from_tag_strips_v() {
        assert_eq!(version_from_tag("v0.4.0"), "0.4.0");
        assert_eq!(version_from_tag("0.4.0"), "0.4.0");
        assert_eq!(version_from_tag("v1.2.3-rc1"), "1.2.3-rc1");
    }

    #[test]
    fn test_find_platform_asset_linux_x64() {
        let release = GitHubRelease {
            tag_name: "v0.4.0".to_string(),
            body: None,
            assets: vec![
                GitHubAsset {
                    name: "x0x-linux-x64-gnu.tar.gz".to_string(),
                    browser_download_url: "https://example.com/x0x-linux-x64-gnu.tar.gz"
                        .to_string(),
                },
                GitHubAsset {
                    name: "x0x-linux-x64-gnu.tar.gz.sig".to_string(),
                    browser_download_url: "https://example.com/x0x-linux-x64-gnu.tar.gz.sig"
                        .to_string(),
                },
            ],
        };

        let (archive_url, sig_url) =
            find_platform_asset(&release, "x86_64-unknown-linux-gnu", "x0xd").unwrap();
        assert!(archive_url.contains("linux-x64-gnu.tar.gz"));
        assert!(sig_url.contains(".sig"));
    }

    #[test]
    fn test_find_platform_asset_missing_archive() {
        let release = GitHubRelease {
            tag_name: "v0.4.0".to_string(),
            body: None,
            assets: vec![],
        };

        let result = find_platform_asset(&release, "x86_64-unknown-linux-gnu", "x0xd");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_platform_asset_unsupported() {
        let release = GitHubRelease {
            tag_name: "v0.4.0".to_string(),
            body: None,
            assets: vec![],
        };

        let result = find_platform_asset(&release, "mips-unknown-linux-gnu", "x0xd");
        assert!(result.is_err());
    }
}
