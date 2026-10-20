#![allow(clippy::expect_used)]

//! #1370: the installed CLI delegates apply to the existing daemon route.
//! Request dumping executes the real CLI dispatch and never sends a request.

use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn apply_request(extra: &[&str]) -> Value {
    let scratch = TempDir::new().expect("CLI scratch directory");
    let output = Command::new(env!("CARGO_BIN_EXE_x0x"))
        .args([
            "--api",
            "http://127.0.0.1:1",
            "--dump-request",
            "upgrade",
            "--apply",
        ])
        .args(extra)
        .current_dir(scratch.path())
        .env("X0X_HOME", scratch.path())
        .env("XDG_DATA_HOME", scratch.path())
        .env("X0X_API_TOKEN", "upgrade-single-writer-fixture")
        .output()
        .expect("run inert CLI request dump");
    assert!(
        output.status.success(),
        "CLI apply must delegate successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.get("method").is_some())
        .collect();
    assert_eq!(requests.len(), 1, "apply must issue exactly one request");
    requests.into_iter().next().expect("one request")
}

#[test]
fn cli_apply_delegates_to_existing_daemon_route() {
    assert_eq!(
        apply_request(&[]),
        serde_json::json!({
            "method": "POST",
            "path": "/upgrade/apply",
            "body": null,
        })
    );
}

#[test]
fn cli_apply_force_does_not_add_a_daemon_bypass() {
    assert_eq!(
        apply_request(&["--force"]),
        serde_json::json!({
            "method": "POST",
            "path": "/upgrade/apply",
            "body": null,
        }),
        "--force is a check option, not a new daemon request field"
    );
}

#[test]
fn bare_cli_upgrade_and_force_do_not_apply() {
    for extra in [vec![], vec!["--force"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_x0x"))
            .args(["--api", "http://127.0.0.1:1", "--dump-request", "upgrade"])
            .args(extra)
            .env("X0X_API_TOKEN", "upgrade-single-writer-fixture")
            .output()
            .expect("run non-applying CLI control");
        assert!(!output.status.success(), "bare upgrade must not apply");
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("\"method\""),
            "only explicit --apply may delegate installation"
        );
    }
}
