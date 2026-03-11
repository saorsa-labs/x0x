use serde::{Deserialize, Serialize};

/// Well-known gossip topic for release notifications.
pub const RELEASE_TOPIC: &str = "x0x/release";

/// Payload published by x0x-bootstrap after a successful self-upgrade.
/// Serialized with bincode for compact wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseNotification {
    /// New release version (semver, e.g. "0.4.0").
    pub version: String,

    /// Per-platform download info. x0xd selects the entry matching its OS/arch.
    pub assets: Vec<PlatformAsset>,

    /// SHA-256 of the SKILL.md included in this release.
    /// x0xd can compare against its local copy to decide whether to update.
    pub skill_sha256: [u8; 32],

    /// Download URL for the new SKILL.md.
    pub skill_url: String,

    /// Unix timestamp (seconds) when this notification was created.
    pub timestamp: u64,
}

/// A platform-specific archive available for download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAsset {
    /// Target triple (e.g. "x86_64-unknown-linux-gnu").
    pub target: String,
    /// URL to the archive (tar.gz or zip).
    pub archive_url: String,
    /// URL to the ML-DSA-65 detached signature (.sig).
    pub signature_url: String,
}

impl ReleaseNotification {
    /// Serialize to bincode bytes.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bincode bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Find the asset matching the given target triple.
    pub fn matches_platform(&self, target: &str) -> Option<&PlatformAsset> {
        self.assets.iter().find(|a| a.target == target)
    }
}

/// Returns the target triple for the current platform.
///
/// Maps (OS, ARCH) to the target triple used in release archive names.
pub fn current_platform_target() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some("x86_64-unknown-linux-gnu")
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Some("aarch64-unknown-linux-gnu")
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Some("x86_64-apple-darwin")
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Some("aarch64-apple-darwin")
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Some("x86_64-pc-windows-msvc")
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    {
        None
    }
}

/// Compare two semver version strings. Returns true if `new` is newer than `current`.
pub fn is_newer(new_version: &str, current_version: &str) -> bool {
    match (
        semver::Version::parse(new_version),
        semver::Version::parse(current_version),
    ) {
        (Ok(new), Ok(current)) => new > current,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_notification() -> ReleaseNotification {
        ReleaseNotification {
            version: "0.4.0".to_string(),
            assets: vec![
                PlatformAsset {
                    target: "x86_64-unknown-linux-gnu".to_string(),
                    archive_url: "https://example.com/x0x-linux-x64-gnu.tar.gz".to_string(),
                    signature_url: "https://example.com/x0x-linux-x64-gnu.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "aarch64-unknown-linux-gnu".to_string(),
                    archive_url: "https://example.com/x0x-linux-arm64-gnu.tar.gz".to_string(),
                    signature_url: "https://example.com/x0x-linux-arm64-gnu.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "x86_64-apple-darwin".to_string(),
                    archive_url: "https://example.com/x0x-macos-x64.tar.gz".to_string(),
                    signature_url: "https://example.com/x0x-macos-x64.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "aarch64-apple-darwin".to_string(),
                    archive_url: "https://example.com/x0x-macos-arm64.tar.gz".to_string(),
                    signature_url: "https://example.com/x0x-macos-arm64.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "x86_64-pc-windows-msvc".to_string(),
                    archive_url: "https://example.com/x0x-windows-x64.zip".to_string(),
                    signature_url: "https://example.com/x0x-windows-x64.zip.sig".to_string(),
                },
            ],
            skill_sha256: [0xAB; 32],
            skill_url: "https://example.com/SKILL.md".to_string(),
            timestamp: 1710000000,
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let notification = make_notification();
        let encoded = notification.encode().unwrap();
        let decoded = ReleaseNotification::decode(&encoded).unwrap();

        assert_eq!(decoded.version, "0.4.0");
        assert_eq!(decoded.assets.len(), 5);
        assert_eq!(decoded.skill_sha256, [0xAB; 32]);
        assert_eq!(decoded.timestamp, 1710000000);
    }

    #[test]
    fn test_platform_matching_correct_target() {
        let notification = make_notification();
        let asset = notification
            .matches_platform("x86_64-unknown-linux-gnu")
            .unwrap();
        assert!(asset.archive_url.contains("linux-x64-gnu"));
    }

    #[test]
    fn test_platform_matching_no_match() {
        let notification = make_notification();
        assert!(notification
            .matches_platform("mips-unknown-linux-gnu")
            .is_none());
    }

    #[test]
    fn test_is_newer_with_newer_version() {
        assert!(is_newer("1.1.0", "1.0.0"));
        assert!(is_newer("2.0.0", "1.9.9"));
        assert!(is_newer("0.4.0", "0.3.1"));
    }

    #[test]
    fn test_is_newer_with_same_or_older() {
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("0.9.0", "1.0.0"));
        assert!(!is_newer("1.0.0", "2.0.0"));
    }

    #[test]
    fn test_is_newer_with_invalid_versions() {
        assert!(!is_newer("not-a-version", "1.0.0"));
        assert!(!is_newer("1.0.0", "not-a-version"));
    }

    #[test]
    fn test_malformed_payload_rejected() {
        let result = ReleaseNotification::decode(b"not valid bincode");
        assert!(result.is_err());
    }

    #[test]
    fn test_current_platform_target_returns_some() {
        // On supported platforms (Linux, macOS, Windows) this should return Some
        #[cfg(any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "windows", target_arch = "x86_64"),
        ))]
        assert!(current_platform_target().is_some());
    }

    #[test]
    fn test_all_platform_assets_matchable() {
        let notification = make_notification();
        let targets = [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ];
        for target in &targets {
            assert!(
                notification.matches_platform(target).is_some(),
                "No match for target: {target}"
            );
        }
    }
}
