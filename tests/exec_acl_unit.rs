use std::path::Path;

use x0x::exec::acl::{
    argv_has_shell_metachar, load_exec_policy, parse_exec_policy, AclError, LoadMode,
};
use x0x::exec::{decode_frame_payload, encode_frame_payload, ExecFrame, ExecPolicy, ExecRequestId};

fn id_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn acl_with_command(argv: &str) -> String {
    format!(
        r#"
[exec]
enabled = true
max_duration_secs = 30
max_concurrent_per_agent = 2
max_concurrent_total = 4
audit_log_path = "/tmp/x0x-exec-test.log"

[[exec.allow]]
description = "alice@laptop"
agent_id = "{}"
machine_id = "{}"

[[exec.allow.commands]]
argv = {argv}
"#,
        id_hex(1),
        id_hex(2),
    )
}

#[test]
fn exact_match_accepts_only_identical_argv() {
    let text = acl_with_command(r#"["systemctl", "status", "x0xd"]"#);
    let policy = parse_exec_policy(Path::new("acl.toml"), 123, &text).expect("valid acl");
    let ExecPolicy::Enabled(acl) = policy else {
        panic!("expected enabled policy")
    };
    let agent = x0x::identity::AgentId([1; 32]);
    let machine = x0x::identity::MachineId([2; 32]);
    let ok = ["systemctl", "status", "x0xd"].map(str::to_string);
    assert!(acl.match_command(&agent, &machine, &ok).is_some());
    let too_long = ["systemctl", "status", "x0xd", "--no-pager"].map(str::to_string);
    assert!(acl.match_command(&agent, &machine, &too_long).is_none());
    let wrong_machine = x0x::identity::MachineId([3; 32]);
    assert!(acl.match_command(&agent, &wrong_machine, &ok).is_none());
}

#[test]
fn int_template_is_restrictive() {
    let text = acl_with_command(r#"["journalctl", "-u", "x0xd", "-n", "<INT>"]"#);
    let policy = parse_exec_policy(Path::new("acl.toml"), 123, &text).expect("valid acl");
    let ExecPolicy::Enabled(acl) = policy else {
        panic!("expected enabled policy")
    };
    let agent = x0x::identity::AgentId([1; 32]);
    let machine = x0x::identity::MachineId([2; 32]);
    for token in ["1", "12345", "999999"] {
        let argv = ["journalctl", "-u", "x0xd", "-n", token].map(str::to_string);
        assert!(
            acl.match_command(&agent, &machine, &argv).is_some(),
            "{token}"
        );
    }
    for token in ["0", "-1", "1000000", "1e5", "1.0", "5`a`"] {
        let argv = ["journalctl", "-u", "x0xd", "-n", token].map(str::to_string);
        assert!(
            acl.match_command(&agent, &machine, &argv).is_none(),
            "{token}"
        );
    }
}

#[test]
fn url_path_template_accepts_only_safe_paths_and_suffixes() {
    let text = acl_with_command(r#"["curl", "-s", "http://127.0.0.1:12600<URL_PATH>"]"#);
    let policy = parse_exec_policy(Path::new("acl.toml"), 123, &text).expect("valid acl");
    let ExecPolicy::Enabled(acl) = policy else {
        panic!("expected enabled policy")
    };
    let agent = x0x::identity::AgentId([1; 32]);
    let machine = x0x::identity::MachineId([2; 32]);
    for path in ["/health", "/foo/bar", "/foo_bar-1.2"] {
        let url = format!("http://127.0.0.1:12600{path}");
        let argv = vec!["curl".to_string(), "-s".to_string(), url];
        assert!(
            acl.match_command(&agent, &machine, &argv).is_some(),
            "{path}"
        );
    }
    for path in ["/..", "/foo bar", "/foo;ls", "health"] {
        let url = format!("http://127.0.0.1:12600{path}");
        let argv = vec!["curl".to_string(), "-s".to_string(), url];
        assert!(
            acl.match_command(&agent, &machine, &argv).is_none(),
            "{path}"
        );
    }
}

#[test]
fn unsupported_template_fails_closed() {
    let text = acl_with_command(r#"["echo", "<ANY>"]"#);
    let err = parse_exec_policy(Path::new("acl.toml"), 123, &text).expect_err("must reject");
    assert!(err.to_string().contains("unsupported template"));
}

#[test]
fn invalid_hex_fails_closed() {
    let text = format!(
        r#"
[exec]
enabled = true
audit_log_path = "/tmp/x0x-exec-test.log"

[[exec.allow]]
agent_id = "not-hex"
machine_id = "{}"

[[exec.allow.commands]]
argv = ["echo", "1"]
"#,
        id_hex(2)
    );
    let err = parse_exec_policy(Path::new("acl.toml"), 123, &text).expect_err("must reject");
    assert!(err.to_string().contains("agent_id"));
}

#[test]
fn shell_metachar_check_is_independent_of_allowlist() {
    let safe = vec![
        "curl".to_string(),
        "http://127.0.0.1:12600/health".to_string(),
    ];
    assert!(!argv_has_shell_metachar(&safe));
    let unsafe_argv = vec!["echo".to_string(), "hello;rm".to_string()];
    assert!(argv_has_shell_metachar(&unsafe_argv));
}

#[test]
fn disabled_policy_when_exec_section_missing_or_false() {
    let missing = parse_exec_policy(Path::new("acl.toml"), 123, "").expect("parse");
    assert!(!missing.enabled());
    let disabled =
        parse_exec_policy(Path::new("acl.toml"), 123, "[exec]\nenabled = false\n").expect("parse");
    assert!(!disabled.enabled());
}

#[tokio::test]
async fn missing_default_acl_disables_but_explicit_missing_errors() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let missing = dir.path().join("missing.toml");
    let policy = load_exec_policy(Some(&missing), LoadMode::DefaultPath)
        .await
        .expect("default missing should disable");
    assert!(!policy.enabled());
    let err = load_exec_policy(Some(&missing), LoadMode::ExplicitPath)
        .await
        .expect_err("explicit missing should error");
    assert!(matches!(err, AclError::Missing(_)));
}

#[test]
fn exec_frame_payload_has_stable_prefix_and_roundtrips() {
    let request_id = ExecRequestId([7; 16]);
    let frame = ExecFrame::Cancel { request_id };
    let payload = encode_frame_payload(&frame).expect("encode");
    assert!(payload.starts_with(x0x::exec::EXEC_DM_PREFIX));
    let decoded = decode_frame_payload(&payload).expect("decode");
    match decoded {
        ExecFrame::Cancel {
            request_id: decoded_id,
        } => assert_eq!(decoded_id, request_id),
        other => panic!("unexpected frame: {other:?}"),
    }
}
