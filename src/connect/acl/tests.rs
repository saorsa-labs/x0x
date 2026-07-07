//! Tests for connect::acl — the fail-closed load matrix (A) and loopback-only
//! target validation matrix (B). See `docs/plans/2026-07-issue-131-connect-acl-plan.md` §5.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::Path;

use super::*;
use crate::exec::acl::{parse_agent_id, parse_machine_id};

// ===========================================================================
// Matrix A — fail-closed load matrix (mirror exec::acl tests one-for-one)
// ===========================================================================

#[tokio::test]
async fn load_policy_missing_file_at_default_path_is_disabled() {
    // A path that definitely doesn't exist, loaded in DefaultPath mode ⇒ Disabled.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("no-such-connect-acl.toml");
    let policy = load_connect_policy(Some(&path), LoadMode::DefaultPath)
        .await
        .unwrap();
    assert!(!policy.enabled());
    if let ConnectPolicy::Disabled { reason, .. } = &policy {
        assert_eq!(reason, "acl_missing");
    } else {
        panic!("expected Disabled");
    }
}

#[tokio::test]
async fn load_policy_missing_file_at_explicit_path_is_hard_error() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("no-such-connect-acl.toml");
    let err = load_connect_policy(Some(&path), LoadMode::ExplicitPath)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ConnectAclError::Missing(_)),
        "ExplicitPath missing ⇒ Missing: {err}"
    );
}

#[tokio::test]
async fn load_policy_malformed_toml_is_hard_error() {
    let path = Path::new("/tmp/x");
    let err = parse_connect_policy(path, 0, "this is not toml {{{").unwrap_err();
    assert!(
        matches!(err, ConnectAclError::Parse { .. }),
        "bad toml ⇒ Parse: {err}"
    );
}

#[test]
fn load_policy_missing_connect_section_is_disabled() {
    let policy = parse_connect_policy(Path::new("/tmp/x"), 0, "[other]\nfoo = 1\n").unwrap();
    if let ConnectPolicy::Disabled { reason, .. } = &policy {
        assert_eq!(reason, "missing_connect_section");
    } else {
        panic!("expected Disabled for missing [connect] section");
    }
}

#[test]
fn load_policy_enabled_false_is_disabled() {
    // enabled defaults to false, so an empty [connect] section disables.
    let policy = parse_connect_policy(Path::new("/tmp/x"), 0, "[connect]\n").unwrap();
    if let ConnectPolicy::Disabled { reason, .. } = &policy {
        assert_eq!(reason, "connect_disabled");
    } else {
        panic!("expected Disabled for enabled=false");
    }
    // explicit false too
    let policy =
        parse_connect_policy(Path::new("/tmp/x"), 0, "[connect]\nenabled = false\n").unwrap();
    assert!(!policy.enabled());
}

#[test]
fn load_policy_unknown_key_is_hard_error() {
    // deny_unknown_fields: a misspelled key must fail loudly.
    let err = parse_connect_policy(
        Path::new("/tmp/x"),
        0,
        "[connect]\nenabled = true\nenable = true\n", // typo: "enable"
    )
    .unwrap_err();
    assert!(
        matches!(err, ConnectAclError::Parse { .. }),
        "unknown field ⇒ Parse: {err}"
    );
}

#[test]
fn load_policy_unknown_key_in_entry_is_hard_error() {
    let err = parse_connect_policy(
        Path::new("/tmp/x"),
        0,
        "[connect]\nenabled = true\n\
         [[connect.allow]]\nagent_id = \"deadbeef\"\nmachine_id = \"deadbeef\"\n\
         targets = [\"127.0.0.1:22\"]\ntaregts = [\"x\"]\n", // typo
    )
    .unwrap_err();
    assert!(
        matches!(err, ConnectAclError::Parse { .. }),
        "unknown entry field ⇒ Parse: {err}"
    );
}

#[test]
fn default_connect_acl_path_returns_expected() {
    let p = default_connect_acl_path();
    let s = p.display().to_string();
    assert!(s.ends_with("connect-acl.toml"), "path: {s}");
}

#[test]
fn connect_policy_default_is_disabled() {
    // The embedded-serve default must be default-deny.
    let p = ConnectPolicy::default();
    assert!(!p.enabled());
    if let ConnectPolicy::Disabled { reason, .. } = &p {
        assert_eq!(reason, "no connect ACL configured");
    } else {
        panic!("default must be Disabled");
    }
}

#[test]
fn connect_policy_enabled_flag_and_path() {
    let p = ConnectPolicy::default();
    assert!(!p.enabled());
    assert_eq!(p.path(), default_connect_acl_path());
    let summary = p.summary();
    assert!(!summary.enabled);
    assert!(summary.disabled_reason.is_some());
}

// ===========================================================================
// Matrix B — loopback-only target validation (every non-loopback = hard error)
// ===========================================================================

fn assert_target_rejected(raw: &str) {
    let err = parse_target(raw).unwrap_err();
    // Sanity: the error message is non-empty and actionable.
    assert!(
        !err.is_empty(),
        "parse_target({raw:?}) rejected with empty message"
    );
}

#[test]
fn target_rejects_lan_and_public_addresses() {
    // Every one of these MUST be a load-time hard error.
    for bad in [
        "192.168.1.10:80",
        "10.0.0.1:22",
        "0.0.0.0:80",
        "8.8.8.8:53",
        "[::]:80",
        "[2001:db8::1]:443",
        "[fe80::1]:22",
    ] {
        assert_target_rejected(bad);
    }
}

#[test]
fn target_rejects_v4_mapped_ipv6() {
    // ::ffff:127.0.0.1 is not loopback under Ipv6Addr::is_loopback — fail-closed.
    let err = parse_target("[::ffff:127.0.0.1]:22").unwrap_err();
    assert!(
        err.contains("127.0.0.1:22") || err.contains("loopback"),
        "v4-mapped message should be actionable: {err}"
    );
}

#[test]
fn target_rejects_hostname_localhost() {
    // localhost does not parse as SocketAddr ⇒ removes the resolver from the TCB.
    let err = parse_target("localhost:22").unwrap_err();
    assert!(
        err.contains("numeric IP") || err.contains("hostname"),
        "hostname rejected: {err}"
    );
}

#[test]
fn target_rejects_port_zero() {
    let err = parse_target("127.0.0.1:0").unwrap_err();
    assert!(err.contains("port 0"), "port 0 rejected: {err}");
}

#[test]
fn target_rejects_leading_zero_octets() {
    // Rust's parser rejects leading-zero octets (octal ambiguity).
    assert_target_rejected("127.000.000.1:22");
}

#[test]
fn target_rejects_missing_port() {
    assert_target_rejected("127.0.0.1");
}

#[test]
fn target_rejects_empty_string() {
    assert_target_rejected("");
}

#[test]
fn target_rejects_empty_targets_list_at_load() {
    let id = "ab".repeat(32);
    let err = parse_connect_policy(
        Path::new("/tmp/x"),
        0,
        &format!(
            "[connect]\nenabled = true\n\
             [[connect.allow]]\nagent_id = \"{id}\"\nmachine_id = \"{id}\"\ntargets = []\n"
        ),
    )
    .unwrap_err();
    assert!(matches!(err, ConnectAclError::Invalid { .. }));
    assert!(format!("{err}").contains("at least one target"));
}

#[test]
fn target_accepts_valid_loopback_addresses() {
    // Accept side: these load successfully.
    assert!(parse_target("127.0.0.1:22").is_ok());
    assert!(parse_target("127.255.255.254:9").is_ok()); // all of 127.0.0.0/8
    assert!(parse_target("[::1]:8080").is_ok());
}

// ===========================================================================
// Matrix B continued — full-file load with valid loopback targets
// ===========================================================================

fn valid_agent_hex() -> String {
    // 64 hex chars (32 bytes) — a syntactically valid agent id.
    "ab".repeat(32)
}

#[test]
fn parse_loads_valid_loopback_acl() {
    let toml = format!(
        "[connect]\nenabled = true\n\
         [[connect.allow]]\n\
         description = \"laptop sshd\"\n\
         agent_id = \"{a}\"\n\
         machine_id = \"{m}\"\n\
         targets = [\"127.0.0.1:22\", \"[::1]:8080\"]\n",
        a = valid_agent_hex(),
        m = valid_agent_hex(),
    );
    let policy = parse_connect_policy(Path::new("/tmp/x"), 123, &toml).unwrap();
    let acl = match policy {
        ConnectPolicy::Enabled(a) => a,
        _ => panic!("expected Enabled"),
    };
    assert_eq!(acl.allow.len(), 1);
    assert_eq!(acl.allow[0].targets.len(), 2);
    assert_eq!(acl.loaded_at_unix_ms, 123);
    let summary = ConnectPolicy::Enabled(acl).summary();
    assert!(summary.enabled);
    assert_eq!(summary.target_entry_count, 2);
}

#[test]
fn parse_rejects_non_loopback_target_at_load() {
    let toml = format!(
        "[connect]\nenabled = true\n\
         [[connect.allow]]\nagent_id = \"{a}\"\nmachine_id = \"{m}\"\n\
         targets = [\"192.168.1.5:22\"]\n",
        a = valid_agent_hex(),
        m = valid_agent_hex(),
    );
    let err = parse_connect_policy(Path::new("/tmp/x"), 0, &toml).unwrap_err();
    assert!(matches!(err, ConnectAclError::Invalid { .. }));
}

#[test]
fn parse_rejects_bad_agent_hex_at_load() {
    let toml = "[connect]\nenabled = true\n\
         [[connect.allow]]\nagent_id = \"not-hex\"\nmachine_id = \"ab\"\n\
         targets = [\"127.0.0.1:22\"]\n";
    let err = parse_connect_policy(Path::new("/tmp/x"), 0, toml).unwrap_err();
    assert!(matches!(err, ConnectAclError::Invalid { .. }));
    assert!(format!("{err}").contains("agent_id"));
}

#[test]
fn is_loopback_factored_correctly() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    assert!(is_loopback(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(is_loopback(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254))));
    assert!(is_loopback(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!is_loopback(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(!is_loopback(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    // v4-mapped is NOT loopback
    let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001);
    assert!(!is_loopback(IpAddr::V6(mapped)));
}

// ===========================================================================
// is_allowed exact-triple matching
// ===========================================================================

#[test]
fn is_allowed_exact_triple_semantics() {
    let agent = parse_agent_id(&"ab".repeat(32)).unwrap();
    let machine = parse_machine_id(&"cd".repeat(32)).unwrap();
    let t22: SocketAddr = "127.0.0.1:22".parse().unwrap();
    let t23: SocketAddr = "127.0.0.1:23".parse().unwrap();
    let t_v6: SocketAddr = "[::1]:22".parse().unwrap();
    let acl = ConnectAcl {
        loaded_from: Path::new("/tmp/x").to_path_buf(),
        loaded_at_unix_ms: 0,
        allow: vec![ConnectAllowEntry {
            description: None,
            agent_id: agent,
            machine_id: machine,
            targets: vec![t22],
        }],
    };
    assert!(acl.is_allowed(&agent, &machine, &t22));
    // wrong port
    assert!(!acl.is_allowed(&agent, &machine, &t23));
    // v4 vs v6 are distinct grants
    assert!(!acl.is_allowed(&agent, &machine, &t_v6));
    // wrong pair
    let other_agent = parse_agent_id(&"99".repeat(32)).unwrap();
    assert!(!acl.is_allowed(&other_agent, &machine, &t22));
}

// ===========================================================================
// Matrix D — doc TOML examples parsed correctly
// ===========================================================================

/// The minimal ACL shown in `docs/connect-acl.md` must load as `Enabled`
/// with the expected entry and target counts.
#[test]
fn docs_minimal_acl_example_parses_correctly() {
    let agent_hex = "01".repeat(32);
    let machine_hex = "02".repeat(32);
    let text = format!(
        r#"
[connect]
enabled = true

[[connect.allow]]
description = "ops-laptop"
agent_id = "{agent_hex}"
machine_id = "{machine_hex}"
targets = ["127.0.0.1:22", "127.0.0.1:5900", "[::1]:8080"]
"#
    );
    let policy = parse_connect_policy(Path::new("connect-acl.toml"), 0, &text)
        .expect("docs minimal example must parse");
    let ConnectPolicy::Enabled(acl) = &policy else {
        panic!("expected Enabled policy");
    };
    assert_eq!(acl.allow.len(), 1, "one allow entry");
    assert_eq!(acl.allow[0].targets.len(), 3, "three targets");
    let agent = parse_agent_id(&agent_hex).unwrap();
    let machine = parse_machine_id(&machine_hex).unwrap();
    let t22: SocketAddr = "127.0.0.1:22".parse().unwrap();
    assert!(acl.is_allowed(&agent, &machine, &t22));
}

/// An unknown field in `[connect]` must be a hard parse error
/// (`deny_unknown_fields` — ADR-0019).
#[test]
fn unknown_field_in_connect_section_is_hard_error() {
    let text = r#"
[connect]
enabled = true
taregts = []
"#;
    let result = parse_connect_policy(Path::new("test.toml"), 0, text);
    assert!(result.is_err(), "misspelled field must be an error");
}

/// An unknown field in `[[connect.allow]]` must be a hard parse error.
#[test]
fn unknown_field_in_allow_entry_is_hard_error() {
    let agent_hex = "01".repeat(32);
    let machine_hex = "02".repeat(32);
    let text = format!(
        r#"
[connect]
enabled = true

[[connect.allow]]
agent_id = "{agent_hex}"
machine_id = "{machine_hex}"
targets = ["127.0.0.1:22"]
unknown_key = "surprise"
"#
    );
    let result = parse_connect_policy(Path::new("test.toml"), 0, &text);
    assert!(
        result.is_err(),
        "unknown field in allow entry must be an error"
    );
}

// ===========================================================================
// Plane-specific default path (#189)
// ===========================================================================

#[test]
fn default_connect_acl_path_for_is_plane_scoped_and_safe() {
    // A named instance gets its own default path in the same directory as the
    // base default, named connect-acl-<name>.toml.
    let testnet = default_connect_acl_path_for("testnet");
    let base = default_connect_acl_path();
    let base_dir = base
        .parent()
        .expect("base default connect-ACL path has a parent dir");
    assert_eq!(
        testnet.parent(),
        Some(base_dir),
        "named-instance default lives in the same dir as the base default"
    );
    assert!(
        testnet
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "connect-acl-testnet.toml"),
        "named-instance default must be connect-acl-<name>.toml, got {testnet:?}"
    );

    // The base default is unchanged for unnamed daemons.
    assert_ne!(base, testnet, "named and base defaults must differ");
    assert!(
        base.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "connect-acl.toml"),
        "base default must stay connect-acl.toml, got {base:?}"
    );
}

#[tokio::test]
async fn load_policy_missing_plane_specific_default_is_disabled() {
    // #189: a named instance's plane-specific default, when missing, must be
    // Disabled (NOT a hard error) — matching the base default's fail-closed
    // behaviour so an unconfigured plane stays disabled.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("connect-acl-testnet.toml");
    let policy = load_connect_policy(Some(&path), LoadMode::DefaultPath)
        .await
        .unwrap();
    assert!(!policy.enabled());
    if let ConnectPolicy::Disabled { reason, .. } = &policy {
        assert_eq!(reason, "acl_missing");
    } else {
        panic!("expected Disabled for a missing plane-specific default");
    }
}
