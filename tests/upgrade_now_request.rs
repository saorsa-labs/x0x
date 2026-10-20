//! Real CLI dispatch in dump mode. No HTTP request or daemon is started.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(extra: &[&str]) -> serde_json::Value {
    let base = std::env::var_os("X0X_UPGRADE_STAGING_EVIDENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".planning/upgrade-now-fixtures")
        });
    std::fs::create_dir_all(&base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("cli-now-")
        .tempdir_in(base)
        .unwrap();
    let root = dir.path().canonicalize().unwrap();
    for name in ["home", "tmp", "profiles"] {
        std::fs::create_dir(root.join(name)).unwrap();
    }
    let stdout = std::fs::File::create(root.join("stdout")).unwrap();
    let stderr = std::fs::File::create(root.join("stderr")).unwrap();
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_x0x"))
            .args([
                "--dump-request",
                "--api",
                "127.0.0.1:1",
                "upgrade",
                "--apply",
            ])
            .args(extra)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", root.join("home"))
            .env("XDG_CONFIG_HOME", root.join("home/config"))
            .env("XDG_DATA_HOME", root.join("home/data"))
            .env("XDG_CACHE_HOME", root.join("home/cache"))
            .env("TMPDIR", root.join("tmp"))
            .env("TMP", root.join("tmp"))
            .env("TEMP", root.join("tmp"))
            .env("X0X_API_TOKEN", "owned-inert-fixture-token")
            .env("LLVM_PROFILE_FILE", root.join("profiles/cli-%p-%m.profraw"))
            .current_dir(&root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "inert CLI dump exceeded its bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "CLI dump failed: {}",
        std::fs::read_to_string(root.join("stderr")).unwrap()
    );
    let output = std::fs::read_to_string(root.join("stdout")).unwrap();
    let requests: Vec<serde_json::Value> = output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value.get("method").is_some())
        .collect();
    assert_eq!(
        requests.len(),
        1,
        "one dispatch must build exactly one request"
    );
    assert!(!root.join("home/.x0x").exists());
    requests.into_iter().next().unwrap()
}

#[test]
fn upgrade_now_request_actual_dispatch_emits_only_the_approved_query() {
    for extra in [vec![], vec!["--now"], vec!["--force", "--now"]] {
        let value = request(&extra);
        assert_eq!(value["method"], "POST");
        assert!(value["body"].is_null());
        let path = value["path"].as_str().unwrap();
        let url = reqwest::Url::parse(&format!("http://127.0.0.1:1{path}")).unwrap();
        assert_eq!(url.path(), "/upgrade/apply");
        let query: Vec<_> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let expected = if extra.contains(&"--now") {
            vec![("now".to_string(), "true".to_string())]
        } else {
            vec![]
        };
        assert_eq!(query, expected, "actual dispatched request: {value}");
    }
}
