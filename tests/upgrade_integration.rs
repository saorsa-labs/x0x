//! Integration tests for the upgrade module.
//!
//! Tests ML-DSA-65 sign/verify round-trips, staged rollout distribution,
//! manifest serialization, gossip wire format, and platform matching.

use std::time::Duration;

use tempfile::TempDir;

use x0x::upgrade::manifest::{
    decode_signed_manifest, encode_signed_manifest, is_newer, PlatformAsset, ReleaseManifest,
    SCHEMA_VERSION,
};
use x0x::upgrade::rollout::StagedRollout;
use x0x::upgrade::signature::{
    sign_with_context, verify_binary_signature_with_key, verify_bytes_signature_with_key,
    SIGNING_CONTEXT,
};
use x0x::upgrade::Upgrader;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    use saorsa_pqc::api::sig::ml_dsa_65;
    let dsa = ml_dsa_65();
    let (pk, sk) = dsa.generate_keypair().expect("keygen");
    (pk.to_bytes().to_vec(), sk.to_bytes().to_vec())
}

fn make_manifest(version: &str) -> ReleaseManifest {
    ReleaseManifest {
        schema_version: SCHEMA_VERSION,
        version: version.to_string(),
        timestamp: 1700000000,
        assets: vec![
            PlatformAsset {
                target: "x86_64-unknown-linux-gnu".to_string(),
                archive_url: "https://example.com/x0x-linux-x64-gnu.tar.gz".to_string(),
                archive_sha256: [0xAAu8; 32],
                signature_url: "https://example.com/x0x-linux-x64-gnu.tar.gz.sig".to_string(),
            },
            PlatformAsset {
                target: "aarch64-apple-darwin".to_string(),
                archive_url: "https://example.com/x0x-macos-arm64.tar.gz".to_string(),
                archive_sha256: [0xBBu8; 32],
                signature_url: "https://example.com/x0x-macos-arm64.tar.gz.sig".to_string(),
            },
        ],
        skill_sha256: [0xABu8; 32],
        skill_url: "https://example.com/SKILL.md".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Signature round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn sign_and_verify_roundtrip_bytes() {
    let (pk, sk) = generate_keypair();
    let data = b"hello world, this is a release binary";

    let sig = sign_with_context(&sk, data).expect("sign");
    verify_bytes_signature_with_key(data, &sig, &pk).expect("should verify");
}

#[test]
fn sign_and_verify_roundtrip_file() {
    let (pk, sk) = generate_keypair();
    let dir = TempDir::new().unwrap();
    let binary_path = dir.path().join("test-binary");
    let data = vec![0xCAu8; 4096];
    std::fs::write(&binary_path, &data).unwrap();

    let sig = sign_with_context(&sk, &data).expect("sign");
    verify_binary_signature_with_key(&binary_path, &sig, &pk).expect("should verify");
}

#[test]
fn wrong_key_rejects() {
    let (_pk1, sk1) = generate_keypair();
    let (pk2, _sk2) = generate_keypair();
    let data = b"some binary content";

    let sig = sign_with_context(&sk1, data).expect("sign");
    let result = verify_bytes_signature_with_key(data, &sig, &pk2);
    assert!(result.is_err(), "wrong key should fail verification");
}

#[test]
fn tampered_data_rejects() {
    let (pk, sk) = generate_keypair();
    let data = b"original content";

    let sig = sign_with_context(&sk, data).expect("sign");
    let result = verify_bytes_signature_with_key(b"tampered content", &sig, &pk);
    assert!(result.is_err(), "tampered data should fail verification");
}

#[test]
fn truncated_signature_errors() {
    let (pk, _sk) = generate_keypair();
    let data = b"test data";
    let short_sig = vec![0u8; 100];

    let result = verify_bytes_signature_with_key(data, &short_sig, &pk);
    assert!(result.is_err());
}

#[test]
fn signing_context_is_correct() {
    assert_eq!(SIGNING_CONTEXT, b"x0x-release-v1");
}

// ---------------------------------------------------------------------------
// Staged rollout tests
// ---------------------------------------------------------------------------

#[test]
fn rollout_delays_are_deterministic() {
    let r1 = StagedRollout::new(b"node-abc", 24);
    let r2 = StagedRollout::new(b"node-abc", 24);
    assert_eq!(r1.calculate_delay(), r2.calculate_delay());
}

#[test]
fn rollout_delay_bounded_by_window() {
    for i in 0..50 {
        let id = format!("test-node-{i}");
        let rollout = StagedRollout::new(id.as_bytes(), 4);
        let delay = rollout.calculate_delay();
        assert!(
            delay <= Duration::from_secs(4 * 60),
            "delay {delay:?} exceeds 4 minute window"
        );
    }
}

#[test]
fn rollout_zero_window_gives_zero_delay() {
    let rollout = StagedRollout::new(b"any-node", 0);
    assert_eq!(rollout.calculate_delay(), Duration::ZERO);
}

// ---------------------------------------------------------------------------
// Manifest JSON round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn manifest_json_roundtrip() {
    let manifest = make_manifest("1.5.0");
    let json = serde_json::to_string_pretty(&manifest).expect("serialize");
    let decoded: ReleaseManifest = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(decoded.schema_version, SCHEMA_VERSION);
    assert_eq!(decoded.version, "1.5.0");
    assert_eq!(decoded.assets.len(), 2);
    assert_eq!(decoded.skill_sha256, [0xABu8; 32]);
    assert_eq!(decoded.timestamp, 1700000000);
    assert_eq!(decoded.assets[0].archive_sha256, [0xAAu8; 32]);
}

#[test]
fn manifest_is_newer_detects_upgrade() {
    assert!(is_newer("2.0.0", "1.0.0"));
    assert!(is_newer("1.1.0", "1.0.0"));
    assert!(!is_newer("1.0.0", "1.0.0"));
    assert!(!is_newer("0.9.0", "1.0.0"));
}

#[test]
fn manifest_platform_matching() {
    let manifest = make_manifest("1.0.0");

    let linux = manifest.matches_platform("x86_64-unknown-linux-gnu");
    assert!(linux.is_some());
    assert_eq!(linux.unwrap().target, "x86_64-unknown-linux-gnu");

    let mac = manifest.matches_platform("aarch64-apple-darwin");
    assert!(mac.is_some());

    assert!(manifest
        .matches_platform("x86_64-pc-windows-msvc")
        .is_none());
}

#[test]
fn manifest_malformed_json_rejected() {
    let result: Result<ReleaseManifest, _> = serde_json::from_str("not valid json");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Gossip wire format tests
// ---------------------------------------------------------------------------

#[test]
fn manifest_gossip_payload_roundtrip() {
    let manifest = make_manifest("2.0.0");
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    let (_pk, sk) = generate_keypair();
    let sig = sign_with_context(&sk, &manifest_json).expect("sign");

    let payload = encode_signed_manifest(&manifest_json, &sig);
    let (decoded_json, decoded_sig) = decode_signed_manifest(&payload).expect("decode");

    assert_eq!(decoded_json, manifest_json.as_slice());
    assert_eq!(decoded_sig, sig.as_slice());

    // Verify the decoded manifest can be parsed
    let decoded: ReleaseManifest = serde_json::from_slice(decoded_json).expect("parse");
    assert_eq!(decoded.version, "2.0.0");
}

#[test]
fn manifest_signature_roundtrip() {
    let (_pk, sk) = generate_keypair();
    let manifest = make_manifest("3.0.0");
    let manifest_json = serde_json::to_vec(&manifest).unwrap();

    // Sign the manifest JSON
    let sig = sign_with_context(&sk, &manifest_json).expect("sign");

    // Verify using the raw bytes function (same key)
    let (pk, _) = generate_keypair(); // different key — should fail
    let result = verify_bytes_signature_with_key(&manifest_json, &sig, &pk);
    assert!(result.is_err(), "wrong key should fail");
}

#[test]
fn manifest_tampered_rejected() {
    let (pk, sk) = generate_keypair();
    let manifest = make_manifest("1.0.0");
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    let sig = sign_with_context(&sk, &manifest_json).expect("sign");

    // Tamper with the manifest
    let mut tampered = manifest_json.clone();
    tampered[10] ^= 0xFF; // flip a byte

    let payload = encode_signed_manifest(&tampered, &sig);
    let (decoded_json, decoded_sig) = decode_signed_manifest(&payload).expect("decode");

    // Tampered data should not match original
    assert_ne!(decoded_json, manifest_json.as_slice());

    // Signature verification should fail on tampered data
    let result = verify_bytes_signature_with_key(decoded_json, decoded_sig, &pk);
    assert!(
        result.is_err(),
        "tampered manifest should fail verification"
    );
}

#[test]
fn manifest_gossip_decode_too_short() {
    let result = decode_signed_manifest(&[0, 0]);
    assert!(result.is_err());
}

#[test]
fn manifest_gossip_decode_truncated() {
    let mut payload = vec![0, 0, 0, 100]; // says 100 bytes of manifest
    payload.extend_from_slice(&[0u8; 6]); // only 6 bytes
    let result = decode_signed_manifest(&payload);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Upgrader backup/restore tests
// ---------------------------------------------------------------------------

#[test]
fn upgrader_backup_and_restore() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("my-binary");
    std::fs::write(&target, b"original binary content").unwrap();

    let version = semver::Version::new(1, 0, 0);
    let upgrader = Upgrader::new(target.clone(), version);
    let backup = upgrader.create_backup().expect("backup");

    std::fs::write(&target, b"corrupted").unwrap();

    upgrader.restore_from_backup(&backup).expect("restore");
    let restored = std::fs::read(&target).unwrap();
    assert_eq!(restored, b"original binary content");
}

#[test]
fn upgrader_atomic_replace() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("binary");
    let new_binary = dir.path().join("new-binary");
    std::fs::write(&target, b"old").unwrap();
    std::fs::write(&new_binary, b"new").unwrap();

    let version = semver::Version::new(1, 0, 0);
    let upgrader = Upgrader::new(target.clone(), version);
    upgrader.atomic_replace(&new_binary).expect("replace");

    assert_eq!(std::fs::read(&target).unwrap(), b"new");
}

#[test]
fn upgrader_rejects_downgrade() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("binary");
    std::fs::write(&target, b"data").unwrap();

    let version = semver::Version::new(2, 0, 0);
    let upgrader = Upgrader::new(target, version);

    // Downgrade should fail
    let old = semver::Version::new(1, 0, 0);
    assert!(upgrader.validate_upgrade(&old).is_err());

    // Same version should fail
    let same = semver::Version::new(2, 0, 0);
    assert!(upgrader.validate_upgrade(&same).is_err());

    // Upgrade should succeed
    let newer = semver::Version::new(3, 0, 0);
    assert!(upgrader.validate_upgrade(&newer).is_ok());
}

#[test]
fn max_binary_size_constant() {
    assert_eq!(x0x::upgrade::MAX_BINARY_SIZE_BYTES, 200 * 1024 * 1024);
}

// ---------------------------------------------------------------------------
// End-to-end: sign → write → verify from file
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_sign_write_verify() {
    let (pk, sk) = generate_keypair();
    let dir = TempDir::new().unwrap();

    let binary_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let binary_path = dir.path().join("x0x-bootstrap");
    std::fs::write(&binary_path, &binary_data).unwrap();

    let sig = sign_with_context(&sk, &binary_data).expect("sign");

    let sig_path = dir.path().join("x0x-bootstrap.sig");
    std::fs::write(&sig_path, &sig).unwrap();

    let sig_from_file = std::fs::read(&sig_path).unwrap();
    verify_binary_signature_with_key(&binary_path, &sig_from_file, &pk).expect("should verify");
}
