//! #2008: queued durable DMs (#1109) between two real x0xd daemons.
//!
//! The #1109 unit tests drive the outbox worker with a scripted transport.
//! These tests run two daemons on loopback (no bootstrap seeds, no mDNS, a
//! private gossip plane; see `harness/src/daemon.rs`) and check what a
//! caller sees through the REST API:
//!
//! - Cold recipient: alice knows bob only as a contact (no card, so no
//!   capability advert) and bob is offline. A synchronous send answers 409
//!   `recipient_ack_semantics_unavailable`; a queued send is held with that
//!   error. Bob comes online, his advert reaches alice, and the held send is
//!   delivered once.
//! - Lost ACK: bob is stopped (SIGSTOP), so a synchronous durable send
//!   answers 504 `timeout` (`outcome: "ack_unknown"`) and the queued send's
//!   first attempt times out and reads `queued`. Alice is killed (SIGKILL)
//!   and bob continues (SIGCONT): bob commits the buffered queued send and
//!   its ACK has no sender to reach. Alice restarts on the same data dir; the
//!   send is still held, the ACK of the next attempt settles it as
//!   `delivered`, and bob holds one copy.
//!
//! Every wait is a bounded poll on an API answer. Daemons are killed on drop.
//! Run with
//! `python3 scripts/dev/test-isolated.py nextest --all-features -- -E 'binary(queued_dm_two_daemon)'`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Longer than any single daemon answer, including a synchronous 504.
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn queued_send_to_cold_recipient_is_held_then_delivered_once() {
    let alice = DaemonFixture::start("qdm-cold-alice").await;
    let mut bob = DaemonFixture::start("qdm-cold-bob").await;
    let bob_id = agent_id(&bob).await;
    let alice_id = agent_id(&alice).await;
    // Bob knows alice by card. Alice knows bob only as a contact: no card,
    // so no capability advert. Neither has a bootstrap peer, so they have
    // not met.
    import_card(&bob, &alice).await;
    let (status, body) = post(
        &alice,
        "/contacts",
        &json!({ "agent_id": bob_id, "trust_level": "trusted" }),
    )
    .await;
    assert!(status.is_success(), "add contact: {status} {body}");
    bob.kill();

    let (status, body) = post(
        &alice,
        "/direct/send",
        &send_body(&bob_id, b"sync-cold", None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "cold sync send: {body}");
    assert_eq!(
        body["error"], "recipient_ack_semantics_unavailable",
        "{body}"
    );

    let payload = format!("qdm-cold-{}", rand::random::<u64>()).into_bytes();
    let logical_id = format!("qdm-cold-{}", rand::random::<u32>());
    let request_id = queue_send(&alice, &bob_id, &payload, &logical_id).await;

    // The worker tried it and held it: retryable, still in the outbox.
    let held = poll_until(
        "the worker holds the cold send",
        Duration::from_secs(30),
        || attempted_obligation(&alice, &request_id),
    )
    .await;
    assert_eq!(
        held["last_error"], "recipient_ack_semantics_unavailable",
        "{held}"
    );
    assert_eq!(
        receipt(&alice, &logical_id, &bob_id).await["status"],
        "queued"
    );

    // Bob comes online with alice as its bootstrap peer; his advert reaches
    // alice, and the held send goes out.
    set_bootstrap_peer(&bob, &quic_addr(&alice).await);
    bob.restart().await;

    let settled = poll_until("the held send settles", Duration::from_secs(90), || {
        settled_receipt(&alice, &logical_id, &bob_id)
    })
    .await;
    assert_settled_delivered(&settled, &payload);
    wait_until_left_outbox(&alice, &request_id).await;
    // Bob commits before it ACKs, so its copy is in history now.
    assert_eq!(
        inbound_copies(&bob, &alice_id, &payload).await,
        1,
        "bob must hold exactly one copy"
    );
}

#[tokio::test]
async fn lost_ack_then_sender_restart_settles_delivered_without_second_copy() {
    let bob = DaemonFixture::start("qdm-ack-bob").await;
    let mut alice = DaemonFixture::start_with_config(
        "qdm-ack-alice",
        &format!("bootstrap_peers = [\"{}\"]\n", quic_addr(&bob).await),
    )
    .await;
    import_card(&alice, &bob).await;
    import_card(&bob, &alice).await;
    let bob_id = agent_id(&bob).await;
    let alice_id = agent_id(&alice).await;
    // Warm-up: one durable send round trip proves the path before the test
    // breaks it.
    poll_until(
        "a warm-up durable send is delivered",
        Duration::from_secs(60),
        || async {
            let (status, body) = post(
                &alice,
                "/direct/send",
                &send_body(&bob_id, b"warm-up", None),
            )
            .await;
            if status == StatusCode::OK {
                Ok(())
            } else {
                Err(format!("{status} {body}"))
            }
        },
    )
    .await;

    // 504 while the recipient cannot answer.
    signal(bob.pid(), "STOP");
    let stopped_at = Instant::now();
    let sync_logical_id = format!("qdm-sync-{}", rand::random::<u32>());
    let sync_body = send_body(&bob_id, b"sync-to-stopped-bob", Some(&sync_logical_id));
    let (status, body) = post(&alice, "/direct/send", &sync_body).await;
    assert_eq!(
        status,
        StatusCode::GATEWAY_TIMEOUT,
        "sync send to a stopped peer: {body}"
    );
    assert_eq!(body["error"], "timeout", "{body}");
    assert_eq!(body["outcome"], "ack_unknown", "{body}");
    assert_eq!(body["logical_id"], sync_logical_id.as_str(), "{body}");
    signal(bob.pid(), "CONT");
    eprintln!("bob stopped for {:?} (sync send)", stopped_at.elapsed());
    let late = poll_until("the 504 send settles", Duration::from_secs(60), || async {
        let body = receipt(&alice, &sync_logical_id, &bob_id).await;
        match body["status"].as_str() {
            Some("pending") => Err(body.to_string()),
            _ => Ok(body),
        }
    })
    .await;
    // The late ACK is recorded: bob committed the 504 send after all.
    assert_eq!(late["status"], "delivered_late", "{late}");
    assert_eq!(
        late["payload_digest"].as_str(),
        Some(blake3::hash(b"sync-to-stopped-bob").to_hex().as_str()),
        "{late}"
    );

    // Lost ACK of a queued send.
    signal(bob.pid(), "STOP");
    let stopped_at = Instant::now();
    let payload = format!("qdm-ack-{}", rand::random::<u64>()).into_bytes();
    let logical_id = format!("qdm-ack-{}", rand::random::<u32>());
    let request_id = queue_send(&alice, &bob_id, &payload, &logical_id).await;
    let held = poll_until(
        "the first attempt ends unacked",
        Duration::from_secs(30),
        || attempted_obligation(&alice, &request_id),
    )
    .await;
    eprintln!("first queued attempt ended with {}", held["last_error"]);
    assert_eq!(
        receipt(&alice, &logical_id, &bob_id).await["status"],
        "queued"
    );

    // The sender dies; bob continues, commits the buffered send, and its
    // ACK has no sender to reach.
    alice.kill();
    signal(bob.pid(), "CONT");
    eprintln!("bob stopped for {:?} (queued send)", stopped_at.elapsed());
    poll_until("bob commits the send", Duration::from_secs(60), || async {
        match inbound_copies(&bob, &alice_id, &payload).await {
            0 => Err("no copy at bob yet".to_string()),
            n => Ok(n),
        }
    })
    .await;
    assert!(
        held_obligation(&alice, &request_id).is_some(),
        "the send stays held on disk"
    );

    alice.restart().await;
    let settled = poll_until("the held send settles", Duration::from_secs(120), || {
        settled_receipt(&alice, &logical_id, &bob_id)
    })
    .await;
    assert_settled_delivered(&settled, &payload);
    wait_until_left_outbox(&alice, &request_id).await;
    assert_eq!(
        inbound_copies(&bob, &alice_id, &payload).await,
        1,
        "the retry after the restart must not store a second copy"
    );
}

/// Poll `probe` every 250 ms until it answers `Ok` or `within` ends.
async fn poll_until<T, F, Fut>(what: &str, within: Duration, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let last = match probe().await {
            Ok(value) => return value,
            Err(last) => last,
        };
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out after {within:?} waiting until {what}; last: {last}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn get(daemon: &DaemonFixture, path: &str) -> (StatusCode, Value) {
    let response = daemon
        .authed_client(HTTP_TIMEOUT)
        .get(daemon.url(path))
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path}: {e}"));
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn post(daemon: &DaemonFixture, path: &str, body: &Value) -> (StatusCode, Value) {
    let response = daemon
        .authed_client(HTTP_TIMEOUT)
        .post(daemon.url(path))
        .json(body)
        .send()
        .await
        .unwrap_or_else(|e| panic!("POST {path}: {e}"));
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}

fn send_body(recipient: &str, payload: &[u8], logical_id: Option<&str>) -> Value {
    let mut body = json!({ "agent_id": recipient, "payload": B64.encode(payload) });
    if let Some(logical_id) = logical_id {
        body["logical_id"] = json!(logical_id);
    }
    body
}

/// POST a queued send (deadline 10 minutes ahead); returns its request id.
async fn queue_send(
    alice: &DaemonFixture,
    bob_id: &str,
    payload: &[u8],
    logical_id: &str,
) -> String {
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let mut body = send_body(bob_id, payload, Some(logical_id));
    body["deliver_until_ms"] = json!(now_ms + 600_000);
    let (status, body) = post(alice, "/direct/send", &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "queued send: {body}");
    assert_eq!(body["outcome"], "queued", "{body}");
    body["request_id"].as_str().unwrap().to_string()
}

async fn agent_id(daemon: &DaemonFixture) -> String {
    let (_, body) = get(daemon, "/agent").await;
    body["agent_id"].as_str().expect("agent_id").to_string()
}

/// `into` imports `from`'s card as a trusted contact.
async fn import_card(into: &DaemonFixture, from: &DaemonFixture) {
    let (_, card) = get(from, "/agent/card").await;
    let link = card["link"].as_str().expect("card link");
    let (status, body) = post(
        into,
        "/agent/card/import",
        &json!({ "card": link, "trust_level": "Trusted" }),
    )
    .await;
    assert!(status.is_success(), "card import: {status} {body}");
}

/// The daemon's QUIC port on loopback.
async fn quic_addr(daemon: &DaemonFixture) -> String {
    let (_, status) = get(daemon, "/network/status").await;
    let addr = status["local_addr"].as_str().expect("local_addr");
    let port = addr.rsplit(':').next().expect("port");
    format!("127.0.0.1:{port}")
}

/// Rewrite the fixture's `bootstrap_peers = []` to `[peer]` before a restart.
fn set_bootstrap_peer(daemon: &DaemonFixture, peer: &str) {
    let config = std::fs::read_to_string(daemon.config_path()).unwrap();
    assert!(config.contains("bootstrap_peers = []\n"), "{config}");
    let config = config.replace(
        "bootstrap_peers = []\n",
        &format!("bootstrap_peers = [\"{peer}\"]\n"),
    );
    std::fs::write(daemon.config_path(), config).unwrap();
}

fn signal(pid: u32, name: &str) {
    let status = std::process::Command::new("kill")
        .arg(format!("-{name}"))
        .arg(pid.to_string())
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{name} {pid}");
}

/// The held obligation for `request_id` in the outbox sidecar, if any.
fn held_obligation(daemon: &DaemonFixture, request_id: &str) -> Option<Value> {
    let text = std::fs::read_to_string(daemon.data_dir().join("direct_send_outbox.json")).ok()?;
    let file: Value = serde_json::from_str(&text).ok()?;
    file["by_recipient"]
        .as_object()?
        .values()
        .filter_map(Value::as_array)
        .flatten()
        .find(|o| o["request_id"] == request_id)
        .cloned()
}

/// The outcome is written before the send leaves the outbox, so a
/// settled receipt can be read a moment before the sidecar drops it.
async fn wait_until_left_outbox(daemon: &DaemonFixture, request_id: &str) {
    poll_until(
        "the send leaves the outbox",
        Duration::from_secs(10),
        || async {
            match held_obligation(daemon, request_id) {
                None => Ok(()),
                Some(o) => Err(o.to_string()),
            }
        },
    )
    .await;
}

/// `Ok` once the worker finished one attempt and kept the send.
async fn attempted_obligation(daemon: &DaemonFixture, request_id: &str) -> Result<Value, String> {
    match held_obligation(daemon, request_id) {
        Some(o) if o["retry_count"].as_u64().unwrap_or(0) >= 1 => Ok(o),
        other => Err(format!("{other:?}")),
    }
}

async fn receipt(daemon: &DaemonFixture, logical_id: &str, recipient: &str) -> Value {
    let (status, body) = get(
        daemon,
        &format!("/direct/receipts/{logical_id}?agent_id={recipient}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "receipt: {body}");
    body
}

/// `Ok` once the receipt leaves `queued`.
async fn settled_receipt(
    daemon: &DaemonFixture,
    logical_id: &str,
    recipient: &str,
) -> Result<Value, String> {
    let body = receipt(daemon, logical_id, recipient).await;
    match body["status"].as_str() {
        Some("queued") => Err(body.to_string()),
        _ => Ok(body),
    }
}

fn assert_settled_delivered(settled: &Value, payload: &[u8]) {
    assert_eq!(settled["status"], "delivered", "{settled}");
    assert_eq!(
        settled["payload_digest"].as_str(),
        Some(blake3::hash(payload).to_hex().as_str()),
        "{settled}"
    );
}

/// Inbound rows in `receiver`'s DM history from `sender` with `payload`.
async fn inbound_copies(receiver: &DaemonFixture, sender: &str, payload: &[u8]) -> usize {
    let (status, body) = get(receiver, &format!("/history?scope=dm:{sender}&limit=500")).await;
    assert_eq!(status, StatusCode::OK, "history: {body}");
    body["records"]
        .as_array()
        .map(|records| {
            records
                .iter()
                .filter(|r| r["direction"] == "Inbound")
                .filter(|r| {
                    r["payload"]
                        .as_str()
                        .and_then(|p| B64.decode(p).ok())
                        .is_some_and(|p| p == payload)
                })
                .count()
        })
        .unwrap_or(0)
}
