#![allow(clippy::expect_used)]

//! #1106 S2b: real config defaults and the existing public delay calculator.
//! These tests only construct configuration values, serialize them, and hash
//! bytes. They start no daemon, task, process, store, socket or service.
//! They do not claim that apply triggers already honor the rollout deadline.

use std::time::Duration;

use sha2::{Digest, Sha256};
use x0x::server::DaemonConfig;
use x0x::upgrade::rollout::StagedRollout;

const MACHINE: [u8; 32] = [42; 32];

fn configured_window(config: &DaemonConfig) -> u64 {
    serde_json::to_value(config).expect("serialize public daemon config")["update"]
        ["rollout_window_minutes"]
        .as_u64()
        .expect("serialized rollout window")
}

#[test]
fn compiled_daemon_config_uses_the_ruled_sixty_minute_window() {
    assert_eq!(configured_window(&DaemonConfig::default()), 60);
}

#[test]
fn omitted_update_section_uses_the_ruled_sixty_minute_window() {
    let config: DaemonConfig = toml::from_str("").expect("default TOML config");
    assert_eq!(configured_window(&config), 60);
}

#[test]
fn omitted_update_window_uses_the_ruled_sixty_minute_window() {
    let config: DaemonConfig =
        toml::from_str("[update]\nenabled = true\n").expect("update section without window");
    assert_eq!(configured_window(&config), 60);
}

#[test]
fn explicit_longer_configured_window_is_preserved() {
    let config: DaemonConfig = toml::from_str("[update]\nrollout_window_minutes = 1440\n")
        .expect("explicit rollout window");
    assert_eq!(configured_window(&config), 1440);
}

// Independent integer quotient for the specified leading-64-bit hash fraction.
// Dividing by 2^64 keeps the fraction in [0, 1), including the largest prefix.
fn reference_seconds(machine: &[u8], version: &str, window_seconds: u64) -> u64 {
    let digest = Sha256::digest([machine, version.as_bytes()].concat());
    let prefix = u64::from_be_bytes(digest[..8].try_into().expect("eight-byte hash prefix"));
    u64::try_from((u128::from(prefix) * u128::from(window_seconds)) / (1_u128 << 64))
        .expect("bounded whole-second delay")
}

#[test]
fn version_salted_delay_keeps_integer_precision_for_a_large_valid_window() {
    let minutes = u64::MAX / 60;
    let expected = reference_seconds(&MACHINE, "1.2.3", minutes * 60);
    assert_eq!(expected, 12_977_049_052_995_283_974);
    assert_eq!(
        StagedRollout::new(&MACHINE, minutes)
            .calculate_delay_for_version("1.2.3")
            .as_secs(),
        expected,
        "floating-point rounding must not move the selected due second"
    );
}

#[test]
fn unsalted_compatibility_delay_also_keeps_integer_precision() {
    let minutes = u64::MAX / 60;
    let expected = reference_seconds(&MACHINE, "", minutes * 60);
    assert_eq!(expected, 6_074_901_588_164_687_619);
    assert_eq!(
        StagedRollout::new(&MACHINE, minutes)
            .calculate_delay()
            .as_secs(),
        expected
    );
}

#[test]
fn ordinary_windows_are_bounded_deterministic_and_version_salted() {
    for minutes in [1, 60, 1440] {
        let rollout = StagedRollout::new(&MACHINE, minutes);
        let first = rollout.calculate_delay_for_version("1.2.3");
        let second = rollout.calculate_delay_for_version("1.2.4");
        assert_eq!(first, rollout.calculate_delay_for_version("1.2.3"));
        assert_ne!(first, second, "this fixture changes order between releases");
        for (version, delay) in [("1.2.3", first), ("1.2.4", second)] {
            assert!(delay < Duration::from_secs(minutes * 60));
            assert_eq!(
                delay.as_secs(),
                reference_seconds(&MACHINE, version, minutes * 60)
            );
        }
    }
}

#[test]
fn extreme_minutes_use_a_bounded_representable_seconds_window() {
    let rollout = StagedRollout::new(&MACHINE, u64::MAX);
    for (version, delay) in [
        ("", rollout.calculate_delay()),
        ("1.2.3", rollout.calculate_delay_for_version("1.2.3")),
    ] {
        assert!(delay < Duration::from_secs(u64::MAX));
        assert_eq!(
            delay.as_secs(),
            reference_seconds(&MACHINE, version, u64::MAX)
        );
    }
}

#[test]
fn explicit_zero_calculator_window_remains_compatible() {
    let rollout = StagedRollout::new(&MACHINE, 0);
    assert_eq!(rollout.calculate_delay(), Duration::ZERO);
    assert_eq!(rollout.calculate_delay_for_version("1.2.3"), Duration::ZERO);
}
