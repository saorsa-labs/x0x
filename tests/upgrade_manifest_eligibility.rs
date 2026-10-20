#![allow(clippy::unwrap_used, clippy::expect_used)]

//! M2 S1a manifest regressions. These cases are inert: JSON decoding and
//! timestamp validation only, with no daemon, filesystem or network activity.

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
