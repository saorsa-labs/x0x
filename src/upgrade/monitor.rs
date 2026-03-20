use std::time::Duration;

use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use tracing::{debug, info, warn};

use super::manifest::{encode_signed_manifest, ReleaseManifest};
use super::signature::verify_manifest_signature;
use super::UpgradeError;

/// Maximum age of a manifest timestamp before it is rejected (30 days).
const MAX_MANIFEST_AGE_SECS: u64 = 30 * 24 * 3600;

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

/// A verified release ready for application and/or gossip broadcast.
#[derive(Debug, Clone)]
pub struct VerifiedRelease {
    /// The parsed, signature-verified manifest.
    pub manifest: ReleaseManifest,
    /// The raw manifest JSON bytes (for re-verification or logging).
    pub manifest_json: Vec<u8>,
    /// The ML-DSA-65 signature over manifest_json.
    pub signature: Vec<u8>,
    /// Pre-encoded gossip payload (length-prefixed manifest + signature).
    /// Ready for immediate publish to RELEASE_TOPIC.
    pub gossip_payload: Vec<u8>,
}

/// Monitors GitHub releases for updates.
///
/// Primary update mechanism for x0x-bootstrap (1h poll).
/// Fallback mechanism for x0xd (startup check + 48h poll).
pub struct UpgradeMonitor {
    repo: String,
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

    /// Check GitHub for a newer release with a signed manifest.
    ///
    /// Returns `Some(VerifiedRelease)` if a newer version is available with a valid
    /// signed manifest, `None` otherwise.
    pub async fn check_for_updates(&self) -> Result<Option<VerifiedRelease>, UpgradeError> {
        let release = self.fetch_latest_github_release().await?;

        let latest_version_str = version_from_tag(&release.tag_name);
        let latest_version = Version::parse(latest_version_str).map_err(|e| {
            UpgradeError::ManifestFetchFailed(format!(
                "Invalid version in tag '{}': {e}",
                release.tag_name
            ))
        })?;

        if latest_version <= self.current_version {
            debug!(
                current_version = %self.current_version,
                "Already on latest version {}",
                self.current_version
            );
            return Ok(None);
        }

        info!(
            current_version = %self.current_version,
            new_version = %latest_version,
            "New version available: {}",
            latest_version
        );

        // Fetch and verify the signed manifest
        match self.fetch_verified_manifest(&release).await {
            Ok(verified) => Ok(Some(verified)),
            Err(e) => {
                warn!(error = %e, "Failed to fetch/verify release manifest, falling back to skip");
                Err(e)
            }
        }
    }

    /// Fetch the verified manifest for the current GitHub release, regardless of
    /// whether it's newer than the running version.
    ///
    /// Used for rebroadcasting: after a node restarts on the latest version, it
    /// should still broadcast the manifest so peers who missed the initial gossip
    /// can receive it.
    pub async fn fetch_current_manifest(&self) -> Result<Option<VerifiedRelease>, UpgradeError> {
        let release = self.fetch_latest_github_release().await?;

        match self.fetch_verified_manifest(&release).await {
            Ok(verified) => Ok(Some(verified)),
            Err(e) => {
                warn!(error = %e, "Failed to fetch/verify current release manifest");
                Err(e)
            }
        }
    }

    /// Fetch the latest GitHub release metadata, respecting the prereleases flag.
    async fn fetch_latest_github_release(&self) -> Result<GitHubRelease, UpgradeError> {
        if self.include_prereleases {
            self.fetch_latest_release_including_prereleases()
                .await
                .map_err(UpgradeError::ManifestFetchFailed)
        } else {
            let api_url = format!("https://api.github.com/repos/{}/releases/latest", self.repo);
            debug!("Checking for updates from: {}", api_url);
            self.client
                .get(&api_url)
                .send()
                .await
                .map_err(|e| {
                    UpgradeError::ManifestFetchFailed(format!("GitHub API request failed: {e}"))
                })?
                .error_for_status()
                .map_err(|e| UpgradeError::ManifestFetchFailed(format!("GitHub API error: {e}")))?
                .json::<GitHubRelease>()
                .await
                .map_err(|e| {
                    UpgradeError::ManifestFetchFailed(format!(
                        "Failed to parse GitHub release: {e}"
                    ))
                })
        }
    }

    /// Fetch and verify the signed release manifest from a GitHub release.
    ///
    /// Downloads `release-manifest.json` and `release-manifest.json.sig` from the
    /// release assets, verifies the ML-DSA-65 signature (Stage 1), and returns
    /// a `VerifiedRelease` with pre-encoded gossip payload.
    pub async fn fetch_verified_manifest(
        &self,
        release: &GitHubRelease,
    ) -> Result<VerifiedRelease, UpgradeError> {
        info!("Fetching release manifest from GitHub");

        let manifest_asset = release
            .assets
            .iter()
            .find(|a| a.name == "release-manifest.json")
            .ok_or_else(|| {
                UpgradeError::ManifestFetchFailed("release missing release-manifest.json".into())
            })?;

        let sig_asset = release
            .assets
            .iter()
            .find(|a| a.name == "release-manifest.json.sig")
            .ok_or_else(|| {
                UpgradeError::ManifestFetchFailed(
                    "release missing release-manifest.json.sig".into(),
                )
            })?;

        let manifest_bytes = self
            .client
            .get(&manifest_asset.browser_download_url)
            .send()
            .await
            .map_err(|e| UpgradeError::ManifestFetchFailed(e.to_string()))?
            .error_for_status()
            .map_err(|e| UpgradeError::ManifestFetchFailed(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| UpgradeError::ManifestFetchFailed(e.to_string()))?;

        let sig_bytes = self
            .client
            .get(&sig_asset.browser_download_url)
            .send()
            .await
            .map_err(|e| UpgradeError::ManifestFetchFailed(e.to_string()))?
            .error_for_status()
            .map_err(|e| UpgradeError::ManifestFetchFailed(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| UpgradeError::ManifestFetchFailed(e.to_string()))?;

        // Stage 1: verify manifest signature
        verify_manifest_signature(&manifest_bytes, &sig_bytes).map_err(|e| {
            warn!(error = %e, "Release manifest signature verification failed");
            UpgradeError::ManifestSignatureInvalid
        })?;
        info!("Release manifest signature verified");

        let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| UpgradeError::InvalidManifest(e.to_string()))?;

        // Validate manifest timestamp to prevent replay of old signed manifests
        validate_manifest_timestamp(&manifest)?;

        let manifest_json = manifest_bytes.to_vec();
        let signature = sig_bytes.to_vec();
        let gossip_payload = encode_signed_manifest(&manifest_json, &signature);

        Ok(VerifiedRelease {
            manifest,
            manifest_json,
            signature,
            gossip_payload,
        })
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
}

/// Strip the `v` prefix from a git tag to get the semver version.
pub fn version_from_tag(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Validate that a manifest timestamp is not too old.
///
/// Rejects manifests older than `MAX_MANIFEST_AGE_SECS` to prevent indefinite
/// replay of legitimately signed but outdated manifests.
pub fn validate_manifest_timestamp(manifest: &ReleaseManifest) -> Result<(), UpgradeError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if manifest.timestamp == 0 {
        // Timestamp not set — allow for backward compatibility with older manifests
        debug!("Manifest has no timestamp, skipping age check");
        return Ok(());
    }

    if now > manifest.timestamp && (now - manifest.timestamp) > MAX_MANIFEST_AGE_SECS {
        let age_days = (now - manifest.timestamp) / 86400;
        warn!(
            manifest_timestamp = manifest.timestamp,
            age_days = age_days,
            max_age_days = MAX_MANIFEST_AGE_SECS / 86400,
            "Rejecting stale manifest: {} days old (max {} days)",
            age_days,
            MAX_MANIFEST_AGE_SECS / 86400
        );
        return Err(UpgradeError::InvalidManifest(format!(
            "manifest too old: {} days (max {} days)",
            age_days,
            MAX_MANIFEST_AGE_SECS / 86400
        )));
    }

    Ok(())
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
}
