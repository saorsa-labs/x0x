//! #2048: an existing member of a `private_secure` group follows a later
//! invite join that it never received. Three in-process daemons on a
//! loopback mesh, public API only. `X0X_TEST_DROP_INITIAL_MEMBER_ADDED`
//! makes the owner send no copy of the seat event, so only catch-up can
//! bring the existing member to the new roster and epoch.
//!
//! ```text
//! python3 scripts/dev/test-isolated.py nextest --all-features \
//!   --test issue2048_invite_join_existing_member -- --run-ignored ignored-only
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{json, Value};
use x0x::server::{serve, DaemonConfig, ServerHandle};

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

struct Daemon {
    handle: ServerHandle,
    api: SocketAddr,
    token: String,
    agent_id: String,
    _dir: tempfile::TempDir,
}

fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind probe udp socket");
    sock.local_addr().expect("probe local_addr").port()
}

async fn call(
    client: &reqwest::Client,
    daemon: &Daemon,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = client
        .request(method, format!("http://{}{path}", daemon.api))
        .bearer_auth(&daemon.token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("request");
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn start(client: &reqwest::Client, quic_port: u16, bootstrap: Vec<SocketAddr>) -> Daemon {
    let dir = tempfile::tempdir().expect("tempdir");
    let config: DaemonConfig = serde_json::from_value(json!({
        "api_address": "127.0.0.1:0",
        "bind_address": format!("127.0.0.1:{quic_port}"),
        "bootstrap_peers": bootstrap,
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "update": {"enabled": false},
        "data_dir": dir.path().join("data"),
        "identity_dir": dir.path().join("identity"),
    }))
    .expect("daemon config");
    let handle = serve(config.clone()).await.expect("serve() starts");
    let token = std::fs::read_to_string(config.data_dir.join("api-token"))
        .expect("api token")
        .trim()
        .to_string();
    let mut daemon = Daemon {
        api: handle.local_addr(),
        handle,
        token,
        agent_id: String::new(),
        _dir: dir,
    };
    let (status, agent) = call(client, &daemon, reqwest::Method::GET, "/agent", None).await;
    assert_eq!(status, 200, "GET /agent: {agent}");
    daemon.agent_id = agent["agent_id"].as_str().expect("agent_id").to_string();
    daemon
}

async fn members(client: &reqwest::Client, daemon: &Daemon, group: &str) -> Vec<String> {
    let (_, info) = call(
        client,
        daemon,
        reqwest::Method::GET,
        &format!("/groups/{group}"),
        None,
    )
    .await;
    info["members"]
        .as_array()
        .map(|members| {
            members
                .iter()
                .filter_map(|member| member["agent_id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn join_by_invite(client: &reqwest::Client, owner: &Daemon, joiner: &Daemon, group: &str) {
    let (status, invite) = call(
        client,
        owner,
        reqwest::Method::POST,
        &format!("/groups/{group}/invite"),
        Some(json!({})),
    )
    .await;
    assert!(status < 300, "invite: {status} {invite}");
    let (status, joined) = call(
        client,
        joiner,
        reqwest::Method::POST,
        "/groups/join",
        Some(json!({"invite": invite["invite_link"], "display_name": "member"})),
    )
    .await;
    assert!(status < 300, "join: {status} {joined}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if members(client, owner, group)
            .await
            .contains(&joiner.agent_id)
            && members(client, joiner, group)
                .await
                .contains(&joiner.agent_id)
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the joiner is not seated on the owner and on itself within 60 s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn encrypt(client: &reqwest::Client, daemon: &Daemon, group: &str, text: &str) -> Value {
    let (status, sealed) = call(
        client,
        daemon,
        reqwest::Method::POST,
        &format!("/groups/{group}/secure/encrypt"),
        Some(json!({"payload_b64": BASE64.encode(text)})),
    )
    .await;
    assert_eq!(status, 200, "encrypt: {sealed}");
    sealed
}

async fn decrypt(
    client: &reqwest::Client,
    daemon: &Daemon,
    group: &str,
    sealed: &Value,
) -> (u16, Value) {
    call(
        client,
        daemon,
        reqwest::Method::POST,
        &format!("/groups/{group}/secure/decrypt"),
        Some(json!({"ciphertext_b64": sealed["ciphertext_b64"]})),
    )
    .await
}

async fn existing_member_follows_a_later_invite_join(encrypt_before_join: bool) {
    static DROP_SEAT_EVENTS: std::sync::Once = std::sync::Once::new();
    DROP_SEAT_EVENTS.call_once(|| std::env::set_var("X0X_TEST_DROP_INITIAL_MEMBER_ADDED", "1"));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client");
    let seed = SocketAddr::from(([127, 0, 0, 1], free_udp_port()));
    let a = start(&client, seed.port(), Vec::new()).await;
    let b = start(&client, free_udp_port(), vec![seed]).await;
    let c = start(&client, free_udp_port(), vec![seed]).await;

    let (status, created) = call(
        &client,
        &a,
        reqwest::Method::POST,
        "/groups",
        Some(json!({"name": "issue 2048", "display_name": "a", "preset": "private_secure"})),
    )
    .await;
    assert!(status < 300, "create: {status} {created}");
    let group = created["group_id"].as_str().expect("group_id").to_string();

    join_by_invite(&client, &a, &b, &group).await;
    if encrypt_before_join {
        let sealed = encrypt(&client, &a, &group, "before the join").await;
        let (status, opened) = decrypt(&client, &b, &group, &sealed).await;
        assert_eq!(status, 200, "B opens the pre-join message: {opened}");
    }
    join_by_invite(&client, &a, &c, &group).await;
    assert!(
        !members(&client, &b, &group).await.contains(&c.agent_id),
        "the seat event reached B, so this run does not test catch-up"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut statuses = Vec::new();
    loop {
        let sealed = encrypt(&client, &a, &group, "after the join").await;
        let (status, opened) = decrypt(&client, &b, &group, &sealed).await;
        statuses.push(status);
        if status == 200 {
            assert_eq!(
                opened["payload_b64"],
                json!(BASE64.encode("after the join"))
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "B cannot open A's post-join messages for 60 s: {statuses:?}, last {opened}; \
             B lists {:?}",
            members(&client, &b, &group).await
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    for (name, daemon) in [("A", &a), ("B", &b), ("C", &c)] {
        let listed = members(&client, daemon, &group).await;
        for member in [&a, &b, &c] {
            assert!(
                listed.contains(&member.agent_id),
                "{name} does not list {}: {listed:?}",
                member.agent_id
            );
        }
    }
    for daemon in [c, b, a] {
        let _ = daemon.handle.shutdown_and_wait().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn existing_member_follows_a_later_invite_join_and_rekey() {
    existing_member_follows_a_later_invite_join(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn existing_member_follows_a_later_invite_join_after_an_earlier_message() {
    existing_member_follows_a_later_invite_join(true).await;
}
