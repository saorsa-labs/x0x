use serde::{Deserialize, Serialize};

use super::UpgradeError;

/// Well-known gossip topic for release notifications.
pub const RELEASE_TOPIC: &str = "x0x/release";

/// Current manifest schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Signed release manifest published via gossip and attached to GitHub releases.
/// Serialized as JSON for human readability and debuggability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub version: String,
    pub timestamp: u64,
    pub assets: Vec<PlatformAsset>,
    pub skill_url: String,
    #[serde(with = "hex_bytes_32")]
    pub skill_sha256: [u8; 32],
}

/// A platform-specific archive available for download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAsset {
    /// Target triple (e.g. "x86_64-unknown-linux-gnu").
    pub target: String,
    /// URL to the archive (tar.gz or zip).
    pub archive_url: String,
    /// SHA-256 hash of the archive.
    #[serde(with = "hex_bytes_32")]
    pub archive_sha256: [u8; 32],
    /// URL to the ML-DSA-65 detached signature (.sig).
    pub signature_url: String,
}

impl ReleaseManifest {
    /// Find the asset matching the current platform.
    pub fn asset_for_current_platform(&self) -> Option<&PlatformAsset> {
        let target = current_platform_target()?;
        self.assets.iter().find(|a| a.target == target)
    }

    /// Find the asset matching the given target triple.
    pub fn matches_platform(&self, target: &str) -> Option<&PlatformAsset> {
        self.assets.iter().find(|a| a.target == target)
    }
}

/// Encode manifest JSON + detached signature for gossip transmission.
///
/// Wire format: `[4-byte BE length][manifest JSON][signature]`
pub fn encode_signed_manifest(manifest_json: &[u8], signature: &[u8]) -> Vec<u8> {
    let len = (manifest_json.len() as u32).to_be_bytes();
    let mut payload = Vec::with_capacity(4 + manifest_json.len() + signature.len());
    payload.extend_from_slice(&len);
    payload.extend_from_slice(manifest_json);
    payload.extend_from_slice(signature);
    payload
}

/// Decode gossip payload into (manifest JSON, signature) slices.
pub fn decode_signed_manifest(payload: &[u8]) -> Result<(&[u8], &[u8]), UpgradeError> {
    if payload.len() < 4 {
        return Err(UpgradeError::InvalidManifest("payload too short".into()));
    }
    let len_bytes: [u8; 4] = payload[..4]
        .try_into()
        .map_err(|_| UpgradeError::InvalidManifest("length prefix not 4 bytes".into()))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if payload.len() < 4 + len {
        return Err(UpgradeError::InvalidManifest(
            "payload truncated: manifest length exceeds payload size".into(),
        ));
    }
    let manifest_json = &payload[4..4 + len];
    let signature = &payload[4 + len..];
    if signature.is_empty() {
        return Err(UpgradeError::InvalidManifest(
            "missing signature after manifest".into(),
        ));
    }
    Ok((manifest_json, signature))
}

/// Returns the target triple for the current platform.
///
/// Maps (OS, ARCH) to the target triple used in release archive names.
/// Includes musl target detection on Linux.
pub fn current_platform_target() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
    {
        return Some("x86_64-unknown-linux-musl");
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", not(target_env = "musl")))]
    {
        return Some("x86_64-unknown-linux-gnu");
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return Some("aarch64-unknown-linux-gnu");
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Some("x86_64-apple-darwin");
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Some("aarch64-apple-darwin");
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return Some("x86_64-pc-windows-msvc");
    }
    #[allow(unreachable_code)]
    None
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

/// Serde helper for [u8; 32] as hex strings in JSON.
mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manifest() -> ReleaseManifest {
        ReleaseManifest {
            schema_version: SCHEMA_VERSION,
            version: "0.5.0".to_string(),
            timestamp: 1710000000,
            assets: vec![
                PlatformAsset {
                    target: "x86_64-unknown-linux-gnu".to_string(),
                    archive_url: "https://example.com/x0x-linux-x64-gnu.tar.gz".to_string(),
                    archive_sha256: [0xAA; 32],
                    signature_url: "https://example.com/x0x-linux-x64-gnu.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "x86_64-unknown-linux-musl".to_string(),
                    archive_url: "https://example.com/x0x-linux-x64-musl.tar.gz".to_string(),
                    archive_sha256: [0xBB; 32],
                    signature_url: "https://example.com/x0x-linux-x64-musl.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "aarch64-unknown-linux-gnu".to_string(),
                    archive_url: "https://example.com/x0x-linux-arm64-gnu.tar.gz".to_string(),
                    archive_sha256: [0xCC; 32],
                    signature_url: "https://example.com/x0x-linux-arm64-gnu.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "x86_64-apple-darwin".to_string(),
                    archive_url: "https://example.com/x0x-macos-x64.tar.gz".to_string(),
                    archive_sha256: [0xDD; 32],
                    signature_url: "https://example.com/x0x-macos-x64.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "aarch64-apple-darwin".to_string(),
                    archive_url: "https://example.com/x0x-macos-arm64.tar.gz".to_string(),
                    archive_sha256: [0xEE; 32],
                    signature_url: "https://example.com/x0x-macos-arm64.tar.gz.sig".to_string(),
                },
                PlatformAsset {
                    target: "x86_64-pc-windows-msvc".to_string(),
                    archive_url: "https://example.com/x0x-windows-x64.zip".to_string(),
                    archive_sha256: [0xFF; 32],
                    signature_url: "https://example.com/x0x-windows-x64.zip.sig".to_string(),
                },
            ],
            skill_sha256: [0xAB; 32],
            skill_url: "https://example.com/SKILL.md".to_string(),
        }
    }

    #[test]
    fn test_json_round_trip() {
        let manifest = make_manifest();
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let decoded: ReleaseManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.schema_version, SCHEMA_VERSION);
        assert_eq!(decoded.version, "0.5.0");
        assert_eq!(decoded.assets.len(), 6);
        assert_eq!(decoded.skill_sha256, [0xAB; 32]);
        assert_eq!(decoded.timestamp, 1710000000);
        assert_eq!(decoded.assets[0].archive_sha256, [0xAA; 32]);
    }

    #[test]
    fn test_encode_decode_round_trip() {
        let manifest_json = b"test manifest json";
        let signature = b"test signature bytes";

        let payload = encode_signed_manifest(manifest_json, signature);
        let (decoded_json, decoded_sig) = decode_signed_manifest(&payload).unwrap();

        assert_eq!(decoded_json, manifest_json);
        assert_eq!(decoded_sig, signature);
    }

    #[test]
    fn test_decode_too_short() {
        let result = decode_signed_manifest(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_truncated() {
        // Length says 100 bytes but payload is only 10
        let mut payload = vec![0, 0, 0, 100];
        payload.extend_from_slice(&[0u8; 6]);
        let result = decode_signed_manifest(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_missing_signature() {
        // Length matches exactly the remaining bytes — no signature
        let manifest = b"hello";
        let len = (manifest.len() as u32).to_be_bytes();
        let mut payload = Vec::new();
        payload.extend_from_slice(&len);
        payload.extend_from_slice(manifest);

        let result = decode_signed_manifest(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_platform_matching_correct_target() {
        let manifest = make_manifest();
        let asset = manifest
            .matches_platform("x86_64-unknown-linux-gnu")
            .unwrap();
        assert!(asset.archive_url.contains("linux-x64-gnu"));
    }

    #[test]
    fn test_platform_matching_musl() {
        let manifest = make_manifest();
        let asset = manifest
            .matches_platform("x86_64-unknown-linux-musl")
            .unwrap();
        assert!(asset.archive_url.contains("linux-x64-musl"));
    }

    #[test]
    fn test_platform_matching_no_match() {
        let manifest = make_manifest();
        assert!(manifest
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
    fn test_current_platform_target_returns_some() {
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
        let manifest = make_manifest();
        let targets = [
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ];
        for target in &targets {
            assert!(
                manifest.matches_platform(target).is_some(),
                "No match for target: {target}"
            );
        }
    }

    #[test]
    fn test_hex_sha256_in_json() {
        let manifest = make_manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        // archive_sha256 for first asset should be hex-encoded 0xAA repeated 32 times
        assert!(json.contains(&"aa".repeat(32)));
    }
}
