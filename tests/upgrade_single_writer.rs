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

// These controls use only a tiny loopback HTTP peer. They never start x0xd,
// construct a network node, load bootstrap peers, or download an artifact.
fn local_http_fixture(
    status: &str,
    body: &str,
) -> (String, std::thread::JoinHandle<Option<String>>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback fixture");
    let address = format!("http://{}", listener.local_addr().expect("fixture address"));
    listener.set_nonblocking(true).expect("bounded listener");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut connection, _)) => {
                    connection
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("bounded request read");
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        let size = connection.read(&mut chunk).expect("fixture request");
                        assert!(size > 0 && request.len() < 8192, "bounded request headers");
                        request.extend_from_slice(&chunk[..size]);
                    }
                    connection
                        .write_all(response.as_bytes())
                        .expect("fixture response");
                    return Some(String::from_utf8(request).expect("HTTP headers"));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        }
        None
    });
    (address, worker)
}

#[test]
fn cli_apply_sends_authentication_to_selected_daemon() {
    let (address, worker) = local_http_fixture("200 OK", r#"{"ok":true,"applied":false}"#);
    let output = Command::new(env!("CARGO_BIN_EXE_x0x"))
        .args(["--api", &address, "upgrade", "--apply"])
        .env("X0X_API_TOKEN", "upgrade-single-writer-fixture")
        .env("NO_PROXY", "*")
        .env("no_proxy", "*")
        .output()
        .expect("run CLI against inert daemon substitute");
    let request = worker.join().expect("fixture worker");
    assert!(
        output.status.success(),
        "CLI daemon delegation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request = request.expect("CLI must contact the selected daemon");
    assert!(request.starts_with("POST /upgrade/apply HTTP/1.1\r\n"));
    assert!(request
        .to_ascii_lowercase()
        .contains("\r\nauthorization: bearer upgrade-single-writer-fixture\r\n"));
    assert_eq!(request.split("\r\n\r\n").nth(1), Some(""));
}

#[test]
fn explicit_check_takes_precedence_over_apply() {
    // The proxy refuses CONNECT immediately. No connection to GitHub exists.
    // A wrong branch would instead emit a dumped daemon apply request.
    let (proxy, worker) = local_http_fixture("502 Bad Gateway", "{}");
    let output = Command::new(env!("CARGO_BIN_EXE_x0x"))
        .args([
            "--api",
            "http://127.0.0.1:1",
            "--dump-request",
            "upgrade",
            "--check",
            "--apply",
        ])
        .env("X0X_API_TOKEN", "upgrade-single-writer-fixture")
        .env("HTTPS_PROXY", &proxy)
        .env("https_proxy", &proxy)
        .env("HTTP_PROXY", &proxy)
        .env("http_proxy", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("all_proxy", &proxy)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .expect("run read-only check against refusing loopback proxy");
    let request = worker.join().expect("proxy worker");
    assert!(
        !output.status.success(),
        "fixture refuses the read-only fetch"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to check for updates"),
        "explicit --check must retain its read-only monitor path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("\"method\""));
    assert!(request
        .expect("monitor must use fixture proxy")
        .starts_with("CONNECT api.github.com:443 "));
}
