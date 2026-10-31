#![allow(clippy::expect_used)]

//! #1106 S2b: real config defaults and the existing public delay calculator.
//! These tests only construct configuration values, serialize them, and hash
//! bytes. They start no daemon, task, process, store, socket or service.
//! They do not claim that apply triggers already honor the rollout deadline.
//! The `*_today` tests pin the current hash construction, including its
//! input collisions, so a later construction change has a red baseline here.

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
// The digest input mirrors the production construction exactly: the raw
// concatenation of machine bytes and version bytes, with no length prefixes.
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

#[test]
fn positive_window_delays_stay_strictly_below_the_window() {
    for minutes in [1, 60, 1440] {
        let window = Duration::from_secs(minutes * 60);
        let rollout = StagedRollout::new(&MACHINE, minutes);
        assert!(rollout.calculate_delay() < window);
        for version in ["", "1.2.3", "9.9.9"] {
            assert!(rollout.calculate_delay_for_version(version) < window);
        }
    }
}

// The three tests below pin today's construction, `SHA-256(node || version)`
// with no length prefixes. They document input collisions of the general
// byte-slice API. The wired path cannot reach them: staging always passes a
// fixed 32-byte machine ID and a bounded canonical semver version, so the
// node width pins the field boundary. A length-prefixed construction must
// flip each `assert_eq!` to `assert_ne!`; see the module docs in
// src/upgrade/rollout.rs for why that change waits for David's ruling.

#[test]
fn variable_width_boundary_shifts_share_one_delay_today() {
    let pair = StagedRollout::new(b"ab", 1440).calculate_delay_for_version("c");
    let shifted = StagedRollout::new(b"a", 1440).calculate_delay_for_version("bc");
    assert_eq!(pair, shifted);
}

#[test]
fn unsalted_delay_matches_node_bytes_sent_as_the_version_today() {
    let node = b"AAAAAAAA";
    let unsalted = StagedRollout::new(node, 1440).calculate_delay();
    let salted = StagedRollout::new(b"", 1440).calculate_delay_for_version("AAAAAAAA");
    assert_eq!(unsalted, salted);
}

#[test]
fn boundary_shift_collision_breaks_both_wired_invariants_today() {
    // `[42; 32] || "9.9.9"` and `[42; 31] || "*9.9.9"` are the same byte
    // stream, because `*` is 0x2a. Each colliding partner breaks a wired
    // invariant: the node is 31 bytes, and "*9.9.9" is not canonical semver.
    let wired = StagedRollout::new(&[42u8; 32], 1440).calculate_delay_for_version("9.9.9");
    let shifted = StagedRollout::new(&[42u8; 31], 1440).calculate_delay_for_version("*9.9.9");
    assert_eq!(wired, shifted);
}
