//! Both-direction file transfer against the pinned v0.47.0 daemon.
//!
//! The peer is tag `57ca3866a816f73cd7df55024c15d3ad8f0f29db`. It does not
//! advertise `file_control_ack_v1` and it does not send `file-control-ack`.
//! A stored offer must still count as success. Accept must finish with the
//! same bytes. Reject must complete on both sides.

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const V047_TAG: &str = "57ca3866a816f73cd7df55024c15d3ad8f0f29db";

struct Daemon {
    child: Child,
    api: String,
    token: String,
    stderr_path: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("udp bind")
        .local_addr()
        .expect("udp addr")
        .port()
}

fn pinned_v047_bin() -> PathBuf {
    if let Ok(path) = std::env::var("X0XD_V047_BIN") {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "X0XD_V047_BIN is not a file: {}",
            path.display()
        );
        return path;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cached = manifest.join("target/v047-pinned/x0xd");
    if cached.is_file() {
        return cached;
    }
    let src = manifest.join("target/v047-src");
    if !src.join("Cargo.toml").is_file() {
        let status = Command::new("git")
            .args(["worktree", "add", "--detach"])
            .arg(&src)
            .arg(V047_TAG)
            .current_dir(&manifest)
            .status()
            .expect("git worktree");
        assert!(status.success(), "git worktree add {V047_TAG} failed");
    }
    let status = Command::new("cargo")
        .args(["build", "--offline", "--locked", "--bin", "x0xd"])
        .current_dir(&src)
        .env("CARGO_BUILD_JOBS", "1")
        .status()
        .expect("cargo build pinned x0xd");
    assert!(status.success(), "pinned v0.47.0 x0xd failed to build");
    fs::create_dir_all(cached.parent().expect("cache parent")).expect("cache dir");
    fs::copy(src.join("target/debug/x0xd"), &cached).expect("copy pinned x0xd");
    cached
}

fn write_config(path: &Path, data: &Path, identity: &Path, udp: u16, plane: &str, bootstrap: u16) {
    let peers = if bootstrap == 0 {
        "bootstrap_peers = []\n".to_string()
    } else {
        format!("bootstrap_peers = [\"127.0.0.1:{bootstrap}\"]\n")
    };
    let text = format!(
        "bind_address = \"127.0.0.1:{udp}\"\n\
         api_address = \"127.0.0.1:0\"\n\
         data_dir = \"{}\"\n\
         identity_dir = \"{}\"\n\
         network_id = \"{plane}\"\n\
         mdns_enabled = false\n\
         port_mapping_enabled = false\n\
         rendezvous_enabled = false\n\
         {peers}\
         [update]\n\
         enabled = false\n\
         [history]\n\
         enabled = false\n",
        data.display(),
        identity.display(),
    );
    fs::write(path, text).expect("write daemon config");
}

fn tail(path: &Path) -> String {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return String::new(),
    };
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if len > 4000 {
        let _ = file.seek(SeekFrom::End(-4000));
    }
    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf);
    buf
}

fn spawn_daemon(
    bin: &Path,
    name: &str,
    root: &Path,
    udp: u16,
    plane: &str,
    bootstrap: u16,
) -> Daemon {
    let home = root.join(name);
    let data = home.join("data");
    let identity = home.join("identity");
    fs::create_dir_all(&data).expect("data dir");
    fs::create_dir_all(&identity).expect("identity dir");
    let config = home.join("config.toml");
    write_config(&config, &data, &identity, udp, plane, bootstrap);
    let stderr_path = home.join("stderr.log");
    let stderr = fs::File::create(&stderr_path).expect("stderr");
    let stdout = fs::File::create(home.join("stdout.log")).expect("stdout");
    let child = Command::new(bin)
        .args([
            "--name",
            name,
            "--config",
            config.to_str().expect("config path"),
            "--no-hard-coded-bootstrap",
            "--no-port-mapping",
        ])
        .env("X0X_HOME", &home)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {} {}: {error}", bin.display(), name));
    let mut daemon = Daemon {
        child,
        api: String::new(),
        token: String::new(),
        stderr_path,
    };
    let port_file = data.join("api.port");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = daemon.child.try_wait().expect("try_wait") {
            panic!(
                "{name} exited {status} before the API came up\n{}",
                tail(&daemon.stderr_path)
            );
        }
        if let Ok(addr) = fs::read_to_string(&port_file) {
            let addr = addr.trim();
            if addr.parse::<SocketAddr>().is_ok() {
                daemon.api = format!("http://{addr}");
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "{name} API did not come up\n{}",
            tail(&daemon.stderr_path)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    daemon.token = fs::read_to_string(data.join("api-token"))
        .expect("api-token")
        .trim()
        .to_string();
    daemon
}

fn client(token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(25))
        .build()
        .expect("client")
}

async fn get_json(daemon: &Daemon, path: &str) -> Value {
    let response = client(&daemon.token)
        .get(format!("{}{path}", daemon.api))
        .send()
        .await
        .unwrap_or_else(|error| {
            panic!(
                "GET {path} {}: {error}\n{}",
                daemon.api,
                tail(&daemon.stderr_path)
            )
        });
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    serde_json::from_str(&text)
        .unwrap_or_else(|_| json!({"http_status": status.as_u16(), "body": text}))
}

async fn agent_hex(daemon: &Daemon) -> String {
    let body = get_json(daemon, "/agent").await;
    body["agent_id"]
        .as_str()
        .unwrap_or_else(|| panic!("agent_id missing: {body}"))
        .to_string()
}

async fn wait_discovered(daemon: &Daemon, peer_hex: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let path = format!("/agents/discovered/{peer_hex}");
    loop {
        let body = get_json(daemon, &path).await;
        if body["ok"] == true {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "never discovered {peer_hex}: {body}\n{}",
            tail(&daemon.stderr_path)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn post_json(daemon: &Daemon, path: &str, body: Value) -> (u16, Value) {
    let response = client(&daemon.token)
        .post(format!("{}{path}", daemon.api))
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|error| panic!("POST {path}: {error}\n{}", tail(&daemon.stderr_path)));
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"body": text}));
    (status, value)
}

async fn send_offer(sender: &Daemon, peer_hex: &str, filename: &str, payload: &[u8]) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = json!({});
    while Instant::now() < deadline {
        let (status, body) = post_json(
            sender,
            "/files/send",
            json!({
                "agent_id": peer_hex,
                "filename": filename,
                "size": payload.len(),
                "sha256": sha_hex(payload),
                "data_b64": base64::engine::general_purpose::STANDARD.encode(payload),
            }),
        )
        .await;
        if status == 500 {
            panic!(
                "v0.47.0 offer must not fail closed: status={status} body={body}\n{}",
                tail(&sender.stderr_path)
            );
        }
        if status == 200 && body["ok"] == true {
            return body["transfer_id"]
                .as_str()
                .unwrap_or_else(|| panic!("transfer_id missing: {body}"))
                .to_string();
        }
        last = body;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!(
        "offer did not succeed: {last}\n{}",
        tail(&sender.stderr_path)
    );
}

fn offer_pending(body: &Value, filename: &str) -> bool {
    body["transfers"].as_array().is_some_and(|transfers| {
        transfers.iter().any(|transfer| {
            transfer["direction"].as_str() == Some("Receiving")
                && transfer["filename"].as_str() == Some(filename)
                && transfer["status"].as_str() == Some("Pending")
        })
    })
}

async fn wait_pending(receiver: &Daemon, filename: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let body = get_json(receiver, "/files/transfers").await;
        if offer_pending(&body, filename) {
            return body["transfers"]
                .as_array()
                .and_then(|transfers| {
                    transfers.iter().find(|transfer| {
                        transfer["filename"].as_str() == Some(filename)
                            && transfer["direction"].as_str() == Some("Receiving")
                    })
                })
                .and_then(|transfer| transfer["transfer_id"].as_str())
                .unwrap_or_else(|| panic!("pending id missing: {body}"))
                .to_string();
        }
        assert!(
            Instant::now() < deadline,
            "remote did not store {filename}: {body}\n{}",
            tail(&receiver.stderr_path)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn status_of(daemon: &Daemon, transfer_id: &str) -> Value {
    get_json(daemon, &format!("/files/transfers/{transfer_id}")).await
}

async fn wait_status(daemon: &Daemon, transfer_id: &str, want: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let body = status_of(daemon, transfer_id).await;
        if body["transfer"]["status"].as_str() == Some(want) {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "{transfer_id} did not become {want}: {body}\n{}",
            tail(&daemon.stderr_path)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn assert_file_bytes(body: &Value, payload: &[u8]) {
    let path = body["transfer"]["output_path"]
        .as_str()
        .unwrap_or_else(|| panic!("output_path missing: {body}"));
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    assert_eq!(bytes, payload, "received bytes differ");
    assert_eq!(
        body["transfer"]["sha256"].as_str(),
        Some(sha_hex(payload).as_str()),
        "sha256 field differs"
    );
}

async fn transfer_round_trip(
    sender: &Daemon,
    receiver: &Daemon,
    peer_hex: &str,
    filename: &str,
    payload: &[u8],
) {
    let sender_id = send_offer(sender, peer_hex, filename, payload).await;
    let receiver_id = wait_pending(receiver, filename).await;
    assert_eq!(
        sender_id, receiver_id,
        "the stored offer must be the sent transfer"
    );
    let (status, body) =
        post_json(receiver, &format!("/files/accept/{receiver_id}"), json!({})).await;
    assert!(
        status == 200 && body["ok"] == true,
        "accept failed: status={status} body={body}\n{}",
        tail(&receiver.stderr_path)
    );
    let sent = wait_status(sender, &sender_id, "Complete").await;
    assert_eq!(sent["transfer"]["status"], "Complete");
    let received = wait_status(receiver, &receiver_id, "Complete").await;
    assert_file_bytes(&received, payload);
}

async fn reject_round_trip(sender: &Daemon, receiver: &Daemon, peer_hex: &str, filename: &str) {
    let payload = filename.as_bytes();
    let sender_id = send_offer(sender, peer_hex, filename, payload).await;
    let receiver_id = wait_pending(receiver, filename).await;
    let (status, body) = post_json(
        receiver,
        &format!("/files/reject/{receiver_id}"),
        json!({"reason": "v047 interop"}),
    )
    .await;
    assert!(
        status == 200 && body["ok"] == true,
        "reject against a v0.47.0 peer must stay success: status={status} body={body}\n{}",
        tail(&receiver.stderr_path)
    );
    let rejected = wait_status(sender, &sender_id, "Rejected").await;
    assert_eq!(rejected["transfer"]["status"], "Rejected");
    let local = status_of(receiver, &receiver_id).await;
    assert_eq!(local["transfer"]["status"], "Rejected");
}

#[tokio::test]
async fn v047_pinned_peer_stores_accepts_and_rejects_both_ways() {
    let old_bin = pinned_v047_bin();
    let new_bin = PathBuf::from(env!("CARGO_BIN_EXE_x0xd"));
    let root = tempfile::tempdir().expect("tempdir");
    let plane = format!("x0x.test.v047file.{:032x}", rand::random::<u128>());
    let old_udp = free_udp_port();
    let new_udp = free_udp_port();
    let old = spawn_daemon(&old_bin, "oldpeer", root.path(), old_udp, &plane, 0);
    let new = spawn_daemon(&new_bin, "newpeer", root.path(), new_udp, &plane, old_udp);
    let old_hex = agent_hex(&old).await;
    let new_hex = agent_hex(&new).await;
    wait_discovered(&old, &new_hex).await;
    wait_discovered(&new, &old_hex).await;

    transfer_round_trip(
        &new,
        &old,
        &old_hex,
        "new-to-old.bin",
        b"new node offer stored by v0.47.0",
    )
    .await;
    transfer_round_trip(
        &old,
        &new,
        &new_hex,
        "old-to-new.bin",
        b"v0.47.0 offer stored by the new node",
    )
    .await;
    reject_round_trip(&new, &old, &old_hex, "new-to-old-reject.bin").await;
    reject_round_trip(&old, &new, &new_hex, "old-to-new-reject.bin").await;
}
