//! GitHub release monitor: polls for new versions, downloads and verifies
//! manifests, and returns `VerifiedRelease` with pre-encoded gossip payloads.

use std::time::Duration;

use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use tracing::{debug, info, warn};

use super::manifest::{encode_signed_manifest, verify_eligible_manifest, ReleaseManifest};
use super::signature::RELEASE_SIGNING_KEY;
use super::UpgradeError;

/// Default GitHub API base URL.
const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";

/// Test-only override of [`DEFAULT_GITHUB_API_BASE`] (issue #1086): lets the
/// server readiness test point every update fetch at a loopback black hole.
/// This seam does not exist in release builds — no environment variable can
/// redirect the update source of a shipped `x0xd`.
#[cfg(test)]
pub(crate) static TEST_API_BASE_OVERRIDE: std::sync::Mutex<Option<String>> =
    std::sync::Mutex::new(None);

/// Resolve the GitHub API base URL: the test-only override when set, else
/// the real GitHub API.
#[cfg(not(test))]
fn github_api_base() -> String {
    DEFAULT_GITHUB_API_BASE.to_string()
}

#[cfg(test)]
fn github_api_base() -> String {
    TEST_API_BASE_OVERRIDE
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| DEFAULT_GITHUB_API_BASE.to_string())
}

/// Maximum age of a manifest timestamp before it is rejected (30 days).
///
/// Applied at every ingestion point — the GitHub-polling monitor here, plus
/// the gossip listener in `x0xd` — so a stale manifest replayed into the
/// network cannot downgrade or re-trigger long-expired upgrades.
pub const MAX_MANIFEST_AGE_SECS: u64 = 30 * 24 * 3600;

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
/// Fallback mechanism for x0xd (startup check + 48h poll).
pub struct UpgradeMonitor {
    repo: String,
    /// Base URL for GitHub API requests ([`github_api_base`]).
    api_base: String,
    current_version: Version,
    client: Client,
    include_prereleases: bool,
}

impl UpgradeMonitor {
    /// Create a new upgrade monitor.
    ///
    /// # Arguments
    /// * `repo` - GitHub repo in "owner/repo" format (e.g. "saorsa-labs/x0x")
    /// * `binary_name` - Name of the binary to extract from archives (e.g. "x0xd", "x0x")
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
            api_base: github_api_base(),
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
    /// signed manifest, `None` otherwise. A current or older release still has a
    /// published version; [`Self::fetch_release_for_check`] keeps it.
    pub async fn check_for_updates(&self) -> Result<Option<VerifiedRelease>, UpgradeError> {
        Ok(self.fetch_release_for_check().await?.update)
    }

    /// Fetched GitHub release, including when it is not an update.
    ///
    /// `check_for_updates` returns only `update`. Callers that print the
    /// published version use this so a current CLI does not hide the release.
    pub(crate) async fn fetch_release_for_check(&self) -> Result<FetchedRelease, UpgradeError> {
        let release = self.fetch_latest_github_release().await?;
        match version_when_not_newer(&self.current_version, &release.tag_name)? {
            Some(version) => {
                debug!(
                    current_version = %self.current_version,
                    release_version = %version,
                    "Already on latest version {}",
                    self.current_version
                );
                Ok(FetchedRelease {
                    version,
                    update: None,
                })
            }
            None => {
                let latest_version = version_from_tag(&release.tag_name);
                info!(
                    current_version = %self.current_version,
                    new_version = %latest_version,
                    "New version available: {}",
                    latest_version
                );
                match self.fetch_verified_manifest(&release).await {
                    Ok(verified) => {
                        let version = verified.manifest.version.clone();
                        Ok(FetchedRelease {
                            version,
                            update: Some(verified),
                        })
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to fetch/verify release manifest, falling back to skip"
                        );
                        Err(e)
                    }
                }
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
            let api_url = format!("{}/repos/{}/releases/latest", self.api_base, self.repo);
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
        self.fetch_verified_manifest_with_key(release, RELEASE_SIGNING_KEY)
            .await
    }

    async fn fetch_verified_manifest_with_key(
        &self,
        release: &GitHubRelease,
        trusted_key: &[u8],
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

        let manifest = verify_eligible_manifest(&manifest_bytes, &sig_bytes, trusted_key)?;

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
        let api_url = format!("{}/repos/{}/releases?per_page=1", self.api_base, self.repo);
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

/// A fetched GitHub release and, when it is newer, its verified manifest.
pub(crate) struct FetchedRelease {
    /// Tag version when this binary is current or ahead. Manifest version
    /// when a newer release verified.
    pub version: String,
    /// Set only when the release is newer and its manifest verifies.
    pub update: Option<VerifiedRelease>,
}

/// Published semver from `tag` when that release is not newer than `current`.
///
/// `Ok(None)` means the tag is newer, so the caller verifies the manifest and
/// uses that version. `Ok(Some)` is the version a current check must keep.
pub(crate) fn version_when_not_newer(
    current: &Version,
    tag: &str,
) -> Result<Option<String>, UpgradeError> {
    let published = version_from_tag(tag);
    let latest = Version::parse(published).map_err(|e| {
        UpgradeError::ManifestFetchFailed(format!("Invalid version in tag '{tag}': {e}"))
    })?;
    if latest <= *current {
        Ok(Some(published.to_string()))
    } else {
        Ok(None)
    }
}

/// Strip the `v` prefix from a git tag to get the semver version.
pub fn version_from_tag(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Enforce manifest eligibility at every ingestion, forwarding and apply boundary.
///
/// The existing name is retained for callers. In addition to timestamp limits,
/// this checks signed channel/version consistency and the unconditional
/// prerelease ban (D186). No configuration flag can bypass these rules.
pub fn validate_manifest_timestamp(manifest: &ReleaseManifest) -> Result<(), UpgradeError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| UpgradeError::InvalidManifest(format!("invalid local clock: {error}")))?
        .as_secs();
    validate_manifest_at(manifest, now)
}

fn validate_manifest_at(manifest: &ReleaseManifest, now: u64) -> Result<(), UpgradeError> {
    let version = Version::parse(&manifest.version)
        .map_err(|error| UpgradeError::InvalidManifest(format!("invalid version: {error}")))?;
    match manifest.channel.as_str() {
        "stable" if version.pre.is_empty() => {}
        "stable" | "prerelease" if (manifest.channel == "stable") != version.pre.is_empty() => {
            return Err(UpgradeError::InvalidManifest(
                "channel/version mismatch".into(),
            ));
        }
        "prerelease" => {
            return Err(UpgradeError::InvalidManifest(
                "prerelease manifests are prohibited".into(),
            ));
        }
        _ => {
            return Err(UpgradeError::InvalidManifest(
                "unknown manifest channel".into(),
            ))
        }
    }
    if manifest.timestamp == 0 {
        return Err(UpgradeError::InvalidManifest(
            "manifest timestamp is zero".into(),
        ));
    }
    const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
    if manifest.timestamp.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
        return Err(UpgradeError::ManifestTimestampInFuture {
            timestamp: manifest.timestamp,
            now,
            max_future_skew_secs: MAX_FUTURE_SKEW_SECS,
        });
    }
    if now.saturating_sub(manifest.timestamp) > MAX_MANIFEST_AGE_SECS {
        return Err(UpgradeError::InvalidManifest(
            "manifest too old: exceeds 30 days".into(),
        ));
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

    #[test]
    fn version_when_not_newer_keeps_the_published_release() {
        let current = Version::parse("1.2.3").unwrap();
        assert_eq!(
            version_when_not_newer(&current, "v1.2.3")
                .unwrap()
                .as_deref(),
            Some("1.2.3")
        );
        assert_eq!(
            version_when_not_newer(&current, "v1.0.0")
                .unwrap()
                .as_deref(),
            Some("1.0.0"),
            "a local build ahead of the release still keeps that release"
        );
        assert!(version_when_not_newer(&current, "v1.3.0")
            .unwrap()
            .is_none());
        assert!(version_when_not_newer(&current, "not-a-version").is_err());
    }

    #[tokio::test]
    async fn current_release_keeps_the_published_release() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await.unwrap();
                let body = br#"{"tag_name":"v1.2.3","assets":[]}"#;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
            }
        });

        let mut current = UpgradeMonitor::new("owner/repo", "x0x", "1.2.3").unwrap();
        current.api_base = format!("http://{addr}");
        let fetched = current.fetch_release_for_check().await.unwrap();
        assert_eq!(fetched.version, "1.2.3");
        assert!(fetched.update.is_none());
        assert!(current.check_for_updates().await.unwrap().is_none());

        let mut ahead = UpgradeMonitor::new("owner/repo", "x0x", "1.4.0").unwrap();
        ahead.api_base = format!("http://{addr}");
        let fetched = ahead.fetch_release_for_check().await.unwrap();
        assert_eq!(fetched.version, "1.2.3");
        assert!(fetched.update.is_none());
    }

    #[test]
    fn validate_manifest_timestamp_accepts_recent() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "0.19.42".to_string(),
            channel: "stable".to_owned(),
            timestamp: now - 3600, // 1 hour ago
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        assert!(validate_manifest_timestamp(&manifest).is_ok());
    }

    #[test]
    fn validate_manifest_timestamp_rejects_old() {
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "0.19.42".to_string(),
            channel: "stable".to_owned(),
            timestamp: 1000000, // way in the past
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        assert!(validate_manifest_timestamp(&manifest).is_err());
    }

    #[test]
    fn validate_manifest_timestamp_rejects_zero() {
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "0.19.42".to_string(),
            channel: "stable".to_owned(),
            timestamp: 0, // missing signed time is not eligible
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        assert!(validate_manifest_timestamp(&manifest).is_err());
    }

    #[test]
    fn validate_manifest_timestamp_rejects_future() {
        let far_future = 9999999999;
        let manifest = ReleaseManifest {
            schema_version: 1,
            version: "0.19.42".to_string(),
            channel: "stable".to_owned(),
            timestamp: far_future,
            assets: vec![],
            skill_url: String::new(),
            skill_sha256: [0u8; 32],
        };
        assert!(validate_manifest_timestamp(&manifest).is_err());
    }

    #[test]
    fn upgrade_monitor_new_parses_version() {
        let monitor = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "0.19.42").unwrap();
        assert_eq!(monitor.repo, "saorsa-labs/x0x");
        assert_eq!(monitor.current_version.to_string(), "0.19.42");
        assert!(!monitor.include_prereleases);
    }

    #[test]
    fn upgrade_monitor_new_rejects_invalid_version() {
        let result = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "not-a-version");
        assert!(result.is_err());
    }

    #[test]
    fn upgrade_monitor_with_prereleases() {
        let monitor = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "0.19.42")
            .unwrap()
            .with_include_prereleases(true);
        assert!(monitor.include_prereleases);
    }

    #[test]
    fn github_release_deserializes() {
        let json = r#"{
            "tag_name": "v0.19.42",
            "body": "Release notes",
            "assets": [
                {"name": "x0d-x86_64-linux-gnu.tar.gz", "browser_download_url": "https://example.com/asset.tar.gz"},
                {"name": "release-manifest.json", "browser_download_url": "https://example.com/manifest.json"},
                {"name": "release-manifest.json.sig", "browser_download_url": "https://example.com/manifest.json.sig"}
            ]
        }"#;
        let release: GitHubRelease = serde_json::from_str(json).unwrap();
        assert_eq!(release.tag_name, "v0.19.42");
        assert_eq!(release.assets.len(), 3);
        assert_eq!(release.assets[0].name, "x0d-x86_64-linux-gnu.tar.gz");
        assert_eq!(release.assets[1].name, "release-manifest.json");
        assert_eq!(release.assets[2].name, "release-manifest.json.sig");
    }

    #[test]
    fn github_release_deserializes_without_body() {
        let json = r#"{
            "tag_name": "v0.18.0",
            "assets": []
        }"#;
        let release: GitHubRelease = serde_json::from_str(json).unwrap();
        assert_eq!(release.tag_name, "v0.18.0");
        assert!(release.body.is_none());
        assert!(release.assets.is_empty());
    }

    async fn serve_manifest_assets(
        manifest_status: &'static str,
        manifest_body: &[u8],
        sig_status: &'static str,
        sig_body: &[u8],
    ) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (manifest_body, sig_body) = (manifest_body.to_vec(), sig_body.to_vec());
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let (status, body) = if req.starts_with("GET /manifest ") {
                    (manifest_status, &manifest_body)
                } else {
                    (sig_status, &sig_body)
                };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
            }
        });
        (
            format!("http://{addr}/manifest"),
            format!("http://{addr}/sig"),
        )
    }

    fn release_with_manifest_urls(manifest_url: String, sig_url: String) -> GitHubRelease {
        GitHubRelease {
            tag_name: "v99.99.99".to_string(),
            body: None,
            assets: vec![
                GitHubAsset {
                    name: "release-manifest.json".to_string(),
                    browser_download_url: manifest_url,
                },
                GitHubAsset {
                    name: "release-manifest.json.sig".to_string(),
                    browser_download_url: sig_url,
                },
            ],
        }
    }

    #[tokio::test]
    async fn signed_manifest_eligibility_on_monitor_and_apply_paths() {
        use serde_json::{json, Value};
        let (public, secret) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let base = json!({"schema_version": 1, "version": "99.99.99", "channel": "stable",
            "timestamp": now, "assets": [], "skill_url": "", "skill_sha256": "00".repeat(32)});
        for (field, value, prerelease_version, eligible) in [
            ("channel", Some(json!("stable")), false, true),
            ("channel", None, false, false),
            ("channel", Some(Value::Null), false, false),
            ("channel", Some(json!(0)), false, false),
            ("channel", Some(json!("")), false, false),
            ("channel", Some(json!("unknown")), false, false),
            ("channel", Some(json!("stable")), true, false),
            ("channel", Some(json!("prerelease")), false, false),
            ("channel", Some(json!("prerelease")), true, false),
            ("timestamp", None, false, false),
            ("timestamp", Some(json!(0)), false, false),
            ("timestamp", Some(json!(now + 3600)), false, false),
            ("timestamp", Some(json!(u64::MAX)), false, false),
            (
                "timestamp",
                Some(json!(now - MAX_MANIFEST_AGE_SECS - 60)),
                false,
                false,
            ),
        ] {
            let mut wire = base.clone();
            if let Some(value) = value {
                wire[field] = value;
            } else {
                wire.as_object_mut().unwrap().remove(field);
            }
            if prerelease_version {
                wire["version"] = json!("99.99.99-rc.1");
            }
            let bytes = serde_json::to_vec(&wire).unwrap();
            let signature =
                super::super::signature::sign_with_context(&secret.to_bytes(), &bytes).unwrap();
            assert_eq!(
                verify_eligible_manifest(&bytes, &signature, &public.to_bytes()).is_ok(),
                eligible,
                "{wire}"
            );
            for include in [false, true] {
                let (url, sig_url) =
                    serve_manifest_assets("200 OK", &bytes, "200 OK", &signature).await;
                let monitor = UpgradeMonitor::new("test/test", "x0xd", "0.1.0")
                    .unwrap()
                    .with_include_prereleases(include);
                let result = monitor
                    .fetch_verified_manifest_with_key(
                        &release_with_manifest_urls(url, sig_url),
                        &public.to_bytes(),
                    )
                    .await;
                assert_eq!(
                    result.is_ok(),
                    eligible,
                    "include_prereleases={include}: {wire}"
                );
            }
            if let Ok(manifest) = serde_json::from_slice::<ReleaseManifest>(&bytes) {
                let result = super::super::apply::AutoApplyUpgrader::new("x0xd")
                    .apply_upgrade_from_manifest(&manifest)
                    .await;
                assert_eq!(
                    matches!(result, Err(UpgradeError::NoPlatformAsset)),
                    eligible,
                    "apply: {wire}"
                );
            }
            let mut tampered = bytes.clone();
            tampered.push(b' ');
            assert!(matches!(
                verify_eligible_manifest(&tampered, &signature, &public.to_bytes()),
                Err(UpgradeError::ManifestSignatureInvalid)
            ));
        }
        let mut manifest: ReleaseManifest = serde_json::from_value(base).unwrap();
        manifest.timestamp = now + 300;
        assert!(validate_manifest_at(&manifest, now).is_ok());
        manifest.timestamp += 1;
        assert!(matches!(
            validate_manifest_at(&manifest, now),
            Err(UpgradeError::ManifestTimestampInFuture {
                max_future_skew_secs: 300,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn fetch_verified_manifest_rejects_missing_manifest_asset() {
        let monitor = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "0.19.42").unwrap();
        let release = GitHubRelease {
            tag_name: "v0.19.43".to_string(),
            body: None,
            assets: vec![GitHubAsset {
                name: "release-manifest.json.sig".to_string(),
                browser_download_url: "https://example.com/manifest.sig".to_string(),
            }],
        };

        let err = monitor.fetch_verified_manifest(&release).await.unwrap_err();
        assert!(format!("{err:?}").contains("release-manifest.json"));
    }

    #[tokio::test]
    async fn fetch_verified_manifest_rejects_missing_signature_asset() {
        let monitor = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "0.19.42").unwrap();
        let release = GitHubRelease {
            tag_name: "v0.19.43".to_string(),
            body: None,
            assets: vec![GitHubAsset {
                name: "release-manifest.json".to_string(),
                browser_download_url: "https://example.com/manifest.json".to_string(),
            }],
        };

        let err = monitor.fetch_verified_manifest(&release).await.unwrap_err();
        assert!(format!("{err:?}").contains("release-manifest.json.sig"));
    }

    #[tokio::test]
    async fn fetch_verified_manifest_rejects_manifest_http_error() {
        let (manifest_url, sig_url) =
            serve_manifest_assets("500 Internal Server Error", b"boom", "200 OK", b"sig").await;
        let monitor = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "0.19.42").unwrap();
        let release = release_with_manifest_urls(manifest_url, sig_url);

        let err = monitor.fetch_verified_manifest(&release).await.unwrap_err();
        assert!(matches!(err, UpgradeError::ManifestFetchFailed(_)));
    }

    #[tokio::test]
    async fn fetch_verified_manifest_rejects_signature_http_error() {
        let manifest = br#"{"schema_version":1,"version":"99.99.99","timestamp":0,"assets":[],"skill_url":"","skill_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let (manifest_url, sig_url) =
            serve_manifest_assets("200 OK", manifest, "404 Not Found", b"missing").await;
        let monitor = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "0.19.42").unwrap();
        let release = release_with_manifest_urls(manifest_url, sig_url);

        let err = monitor.fetch_verified_manifest(&release).await.unwrap_err();
        assert!(matches!(err, UpgradeError::ManifestFetchFailed(_)));
    }

    #[tokio::test]
    async fn fetch_verified_manifest_rejects_invalid_signature_bytes() {
        let manifest = br#"{"schema_version":1,"version":"99.99.99","timestamp":0,"assets":[],"skill_url":"","skill_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let (manifest_url, sig_url) =
            serve_manifest_assets("200 OK", manifest, "200 OK", b"not a valid signature").await;
        let monitor = UpgradeMonitor::new("saorsa-labs/x0x", "x0xd", "0.19.42").unwrap();
        let release = release_with_manifest_urls(manifest_url, sig_url);

        let err = monitor.fetch_verified_manifest(&release).await.unwrap_err();
        assert!(matches!(err, UpgradeError::ManifestSignatureInvalid));
    }
}
