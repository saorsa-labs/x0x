//! #1116: a corrupt revocation store is quarantined, the daemon stays up,
//! status reports the hold, and named-group membership stays closed.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use x0x::revocation::REVOCATION_RESYNC_STATUS;
use x0x::server::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};

struct Daemon {
    _handle: ServerHandle,
    client: reqwest::Client,
    base: String,
}

impl Daemon {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn stop(self) {
        self._handle
            .shutdown_and_wait()
            .await
            .expect("daemon shutdown");
    }
}

async fn start_daemon(dir: &Path) -> Daemon {
    let data_dir = dir.join("data");
    let identity_dir = dir.join("identity");
    tokio::fs::create_dir_all(&data_dir)
        .await
        .expect("create data dir");
    tokio::fs::create_dir_all(&identity_dir)
        .await
        .expect("create identity dir");

    let token = "c0".repeat(32);
    tokio::fs::write(data_dir.join("api-token"), &token)
        .await
        .expect("write api token");

    let mut config = DaemonConfig::default();
    config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bind_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bootstrap_peers = Some(Vec::new());
    config.data_dir = data_dir;
    config.identity_dir = Some(identity_dir);

    let options = ServeOptions {
        skip_update_check: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    };
    let handle = serve_with_options(config, options)
        .await
        .expect("a corrupt revocation store must not refuse startup");
    let base = format!("http://{}", handle.local_addr());

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");

    Daemon {
        _handle: handle,
        client,
        base,
    }
}

#[tokio::test]
async fn corrupt_revocation_store_quarantines_starts_and_reports_1116() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let identity = dir.path().join("identity");
    tokio::fs::create_dir_all(&identity)
        .await
        .expect("identity dir");
    let garbage = b"not a revocation store";
    tokio::fs::write(identity.join("revocations.bin"), garbage)
        .await
        .expect("seed corrupt revocations.bin");
    let daemon = start_daemon(dir.path()).await;

    let mut events = daemon
        .client
        .get(daemon.url("/events"))
        .send()
        .await
        .expect("subscribe to status events");
    assert!(
        events.status().is_success(),
        "the event stream is open while the daemon runs"
    );

    let status: serde_json::Value = daemon
        .client
        .get(daemon.url("/status"))
        .send()
        .await
        .expect("GET /status")
        .json()
        .await
        .expect("status json");
    assert_eq!(status["ok"], true, "the daemon is serving: {status}");
    assert_eq!(status["revocation_resync_required"], true, "{status}");
    let warnings = status["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .filter_map(|warning| warning.as_str())
        .collect::<Vec<_>>();
    assert!(
        warnings.contains(&REVOCATION_RESYNC_STATUS),
        "status event text is missing: {status}"
    );

    let event_text = tokio::time::timeout(Duration::from_secs(5), async {
        let mut collected = String::new();
        while let Some(chunk) = events.chunk().await.expect("read event") {
            collected.push_str(&String::from_utf8_lossy(&chunk));
            if collected.contains(REVOCATION_RESYNC_STATUS) {
                break;
            }
        }
        collected
    })
    .await
    .expect("status event arrives");
    assert!(
        event_text.contains(REVOCATION_RESYNC_STATUS),
        "SSE status event missing the operator sentence: {event_text}"
    );

    let quarantined = std::fs::read_dir(&identity)
        .expect("identity dir")
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("revocations.bin.quarantined-")
        })
        .expect("timestamped quarantine file");
    let name = quarantined.file_name();
    let name = name.to_string_lossy();
    let stamp = name
        .trim_start_matches("revocations.bin.quarantined-")
        .split('-')
        .next()
        .unwrap_or("");
    assert!(
        !stamp.is_empty() && stamp.chars().all(|ch| ch.is_ascii_digit()),
        "quarantine name contains a timestamp: {name}"
    );
    assert_eq!(
        std::fs::read(quarantined.path()).expect("quarantine bytes"),
        garbage
    );
    assert_ne!(
        std::fs::read(identity.join("revocations.bin"))
            .ok()
            .as_deref(),
        Some(garbage.as_slice()),
        "the live path no longer holds the corrupt payload"
    );

    let created: serde_json::Value = daemon
        .client
        .post(daemon.url("/groups"))
        .json(&serde_json::json!({
            "name": "resync-hold",
            "preset": "public_open"
        }))
        .send()
        .await
        .expect("create group")
        .json()
        .await
        .expect("create json");
    assert_eq!(created["ok"], true, "create group: {created}");
    let group_id = created["group_id"].as_str().expect("group_id");

    let members = daemon
        .client
        .get(daemon.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .expect("GET group");
    assert_eq!(members.status(), reqwest::StatusCode::FORBIDDEN);
    let body: serde_json::Value = members.json().await.expect("members json");
    assert_eq!(body["error"], REVOCATION_RESYNC_STATUS, "{body}");

    let quarantine_path = quarantined.path();
    daemon.stop().await;
    std::fs::set_permissions(&quarantine_path, std::fs::Permissions::from_mode(0o000))
        .expect("deny reads of the quarantined payload");
    let again = start_daemon(dir.path()).await;
    let restarted: serde_json::Value = again
        .client
        .get(again.url("/status"))
        .send()
        .await
        .expect("GET /status after restart")
        .json()
        .await
        .expect("restart status json");
    assert_eq!(
        restarted["ok"], true,
        "the next start keeps running: {restarted}"
    );
    assert_eq!(
        restarted["revocation_resync_required"], true,
        "the next start stays closed without reading the quarantined payload: {restarted}"
    );
    assert_ne!(
        std::fs::read(identity.join("revocations.bin"))
            .ok()
            .as_deref(),
        Some(garbage.as_slice()),
        "the next start does not put the corrupt payload back on the live path"
    );
    std::fs::set_permissions(&quarantine_path, std::fs::Permissions::from_mode(0o600))
        .expect("restore quarantine permissions");
    again.stop().await;
}
