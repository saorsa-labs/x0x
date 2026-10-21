//! N7 (charter I13): `x0xd --check` end to end, against the real binary.
//!
//! Complements the unit tests in `src/server/config.rs`, which exercise only
//! the helpers: these fail if the startup refusal, the `--check` failure or the
//! post-`init_logging` warning emission is removed from `src/bin/x0xd.rs`.
//!
//! `--check` loads the config and ACLs, prints and exits: no identity, no
//! sockets, no network. `HOME` and the XDG dirs point at a temp dir so no
//! real `~/.x0x` state is read or written.

use std::path::Path;
use std::process::{Command, Output};

fn check(config_body: &str, extra_args: &[&str]) -> (Output, String) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, config_body).expect("write config");
    let out = run_check(dir.path(), &config, extra_args);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out, text)
}

fn run_check(home: &Path, config: &Path, extra_args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_x0xd"))
        .args(extra_args)
        .arg("--check")
        .arg("--config")
        .arg(config)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn x0xd --check")
}

#[test]
fn nested_network_id_refuses_with_nonzero_exit() {
    // The testnet-on-prod shape. On main this printed "Configuration is valid"
    // and exited 0 with `network_id: None`.
    let (out, text) = check(
        "log_level = 'warn'\n[gossip]\nnetwork_id = 'x0x.testnet'\n",
        &[],
    );
    assert!(!out.status.success(), "must fail: {text}");
    assert!(text.contains("refusing to start"), "{text}");
    assert!(text.contains("`gossip.network_id`"), "{text}");
    assert!(!text.contains("Configuration is valid"), "{text}");
}

#[test]
fn plane_key_in_array_of_tables_refuses() {
    let (out, text) = check("[[testnet]]\nmdns_enabled = false\n", &[]);
    assert!(!out.status.success(), "must fail: {text}");
    assert!(text.contains("`testnet[0].mdns_enabled`"), "{text}");
}

#[test]
fn stray_key_fails_check_and_is_logged_as_a_warning() {
    // Non-fatal at startup, but `--check` fails and names it. The WARN line
    // proves the finding is emitted after `init_logging`: on main it was
    // logged before a subscriber existed and silently dropped.
    let (out, text) = check(
        "log_level = 'warn'\nnetwork_id = 'x0x.testnet'\n[gossip]\nzero_peer_restart_secs = 300\n",
        &[],
    );
    assert!(
        !out.status.success(),
        "--check must fail on a finding: {text}"
    );
    let findings = text.lines().filter(|l| l.starts_with("FINDING")).count();
    assert_eq!(findings, 1, "{text}");
    assert!(text.contains("configuration has 1 finding"), "{text}");
    let warns = text
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("zero_peer_restart_secs"))
        .count();
    assert_eq!(
        warns, 1,
        "the finding must also be logged as a WARN: {text}"
    );
    assert!(!text.contains("refusing to start"), "not fatal: {text}");
}

#[test]
fn named_instance_config_file_without_network_id_refuses() {
    // David, 2026-09-29: a named instance whose config file declares no plane
    // must not start (on main it started on x0x.prod with a warning).
    let (out, text) = check("log_level = 'warn'\n", &["--name", "n7check"]);
    assert!(!out.status.success(), "{text}");
    assert!(
        text.contains("named instance 'n7check' has no network_id"),
        "{text}"
    );
    assert!(!text.contains("Configuration is valid"), "{text}");
}

#[test]
fn named_instance_without_any_config_file_still_starts_on_prod() {
    // `install.sh --name` / `x0x daemon start --name` write no config file:
    // such an instance keeps unset = prod. `--check` reports it as a finding
    // but it is not refused.
    let home = tempfile::tempdir().expect("tmpdir");
    let out = Command::new(env!("CARGO_BIN_EXE_x0xd"))
        .args(["--name", "n7nofile", "--check"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn x0xd --check");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!text.contains("has no network_id"), "not refused: {text}");
    assert!(
        text.contains("named instance `n7nofile` sets no top-level `network_id`"),
        "{text}"
    );
}

/// ADR-0074 §3: `load_config` refuses a non-loopback `[socks] listen`.
/// This is the binary path. `SocksConfig::validate` alone is not the check.
#[test]
fn non_loopback_socks_listen_refuses_check() {
    let (out, text) = check(
        "log_level = 'warn'\n[socks]\nlisten = \"0.0.0.0:1080\"\n",
        &[],
    );
    assert!(!out.status.success(), "must fail: {text}");
    assert!(
        text.to_ascii_lowercase().contains("loopback"),
        "refused for the wrong reason: {text}"
    );
    assert!(!text.contains("Configuration is valid"), "{text}");
}

#[test]
fn clean_config_passes_check() {
    let (out, text) = check(
        "log_level = 'warn'\nnetwork_id = 'x0x.testnet'\nmdns_enabled = false\n[gossip]\n",
        &["--name", "n7check"],
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("Configuration is valid"), "{text}");
    assert!(!text.contains("FINDING"), "{text}");
}
