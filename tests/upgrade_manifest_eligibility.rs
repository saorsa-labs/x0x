#![allow(clippy::unwrap_used, clippy::expect_used)]

//! M2 S1a manifest regressions. These cases are inert: JSON decoding and
//! signature and eligibility validation only, with no daemon or network activity.

use std::time::{SystemTime, UNIX_EPOCH};

use x0x::upgrade::manifest::ReleaseManifest;
use x0x::upgrade::monitor::{validate_manifest_timestamp, MAX_MANIFEST_AGE_SECS};

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn manifest(timestamp: u64) -> ReleaseManifest {
    // Decode original wire-shaped JSON so the red test also compiles before
    // the signed channel field is added to ReleaseManifest.
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "version": "0.48.2",
        "channel": "stable",
        "timestamp": timestamp,
        "assets": [],
        "skill_url": "",
        "skill_sha256": "00".repeat(32),
    }))
    .unwrap()
}

#[test]
fn zero_timestamp_does_not_bypass_manifest_eligibility() {
    assert!(
        validate_manifest_timestamp(&manifest(0)).is_err(),
        "ADR 0094 rejects zero timestamps instead of bypassing the age check"
    );
}

#[test]
fn excessively_future_timestamp_is_not_eligible() {
    // Far outside D182's 300-second skew, with no wall-clock boundary race.
    let future = now_seconds().checked_add(3_600).unwrap();
    assert!(
        validate_manifest_timestamp(&manifest(future)).is_err(),
        "a signed manifest more than five minutes ahead must be refused"
    );
}

#[test]
fn maximum_timestamp_cannot_overflow_into_eligibility() {
    assert!(
        validate_manifest_timestamp(&manifest(u64::MAX)).is_err(),
        "an extreme timestamp must be refused without subtraction overflow"
    );
}

#[test]
fn recent_timestamp_and_permitted_clock_skew_remain_eligible() {
    let now = now_seconds();
    for timestamp in [now.saturating_sub(60), now, now.checked_add(60).unwrap()] {
        assert!(
            validate_manifest_timestamp(&manifest(timestamp)).is_ok(),
            "a recent timestamp or one-minute clock skew remains eligible"
        );
    }
}

#[test]
fn stale_manifest_remains_refused() {
    let stale = now_seconds()
        .checked_sub(MAX_MANIFEST_AGE_SECS + 3_600)
        .unwrap();
    assert!(
        validate_manifest_timestamp(&manifest(stale)).is_err(),
        "the existing thirty-day replay limit remains in force"
    );
}

#[test]
fn required_manifest_fields_and_channel_rules_fail_closed() {
    let valid = serde_json::to_value(manifest(now_seconds())).unwrap();
    for field in ["channel", "timestamp"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<ReleaseManifest>(missing).is_err());
        for bad in [serde_json::Value::Null, serde_json::json!({})] {
            let mut malformed = valid.clone();
            malformed[field] = bad;
            assert!(serde_json::from_value::<ReleaseManifest>(malformed).is_err());
        }
    }
    let mut zero_channel = valid.clone();
    zero_channel["channel"] = serde_json::json!(0);
    assert!(serde_json::from_value::<ReleaseManifest>(zero_channel).is_err());
    for (channel, version) in [
        ("", "0.48.2"),
        ("unknown", "0.48.2"),
        ("Stable", "0.48.2"),
        ("stable", "0.48.2-rc.1"),
        ("prerelease", "0.48.2"),
        ("prerelease", "0.48.2-rc.1"),
    ] {
        let mut candidate = valid.clone();
        candidate["channel"] = channel.into();
        candidate["version"] = version.into();
        let candidate = serde_json::from_value(candidate).unwrap();
        assert!(
            validate_manifest_timestamp(&candidate).is_err(),
            "ineligible channel/version pair {channel:?}/{version}"
        );
    }
}

#[test]
fn test_key_signed_channel_is_accepted_by_pre_channel_schema() {
    use x0x::upgrade::manifest::PlatformAsset;
    use x0x::upgrade::signature::{sign_with_context, verify_bytes_signature_with_key};

    // Frozen pre-channel wire fields from released v0.48.1, commit
    // 8c4ef1744b05e122e49ef5541e2c432a9d9003ee. Unknown fields are ignored.
    #[derive(serde::Deserialize)]
    struct PreChannelManifest {
        schema_version: u32,
        version: String,
        timestamp: u64,
        assets: Vec<PlatformAsset>,
        skill_url: String,
        skill_sha256: String,
    }
    let current = manifest(now_seconds());
    let original_bytes = serde_json::to_vec_pretty(&current).unwrap();
    let (test_public, test_secret) = saorsa_pqc::api::sig::ml_dsa_65()
        .generate_keypair()
        .unwrap();
    let signature = sign_with_context(&test_secret.to_bytes(), &original_bytes).unwrap();
    verify_bytes_signature_with_key(&original_bytes, &signature, &test_public.to_bytes()).unwrap();
    let old: PreChannelManifest = serde_json::from_slice(&original_bytes).unwrap();
    assert_eq!(old.schema_version, current.schema_version);
    assert_eq!(old.version, current.version);
    assert_eq!(old.timestamp, current.timestamp);
    assert_eq!(old.assets.len(), current.assets.len());
    assert_eq!(old.skill_url, current.skill_url);
    assert_eq!(hex::decode(old.skill_sha256).unwrap(), current.skill_sha256);
    validate_manifest_timestamp(&current).unwrap();

    // The ignored field is still signed: changing only channel must fail.
    let tampered = String::from_utf8(original_bytes)
        .unwrap()
        .replace("\"stable\"", "\"prerelease\"");
    assert!(verify_bytes_signature_with_key(
        tampered.as_bytes(),
        &signature,
        &test_public.to_bytes()
    )
    .is_err());
}
