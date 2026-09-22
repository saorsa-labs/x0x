//! #341 live acceptance: encrypted group-store application payloads remain
//! sealed across removal/rekey and daemon restart.
//!
//! Ignored because it starts three real x0xd processes and uses real QUIC.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bincode::Options;
use futures_util::StreamExt;
use reqwest::StatusCode;
use saorsa_gossip_types::PeerId;
use serde_json::Value;
use std::future::Future;
use std::time::Duration;
use tokio::sync::mpsc;
use x0x::kv::encrypted::EncryptedKvStoreRecordV1;

#[path = "harness/src/cluster.rs"]
mod cluster;
use cluster::{trio_with_extra_config, AgentInstance};

const PHASE_TIMEOUT: Duration = Duration::from_secs(45);
const SSE_LAG_MARKER: &str = "SSE client lagged behind broadcast stream";
const APPROVAL_RETRY_MAX_ATTEMPTS: u32 = 200;
const APPROVAL_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const APPROVAL_RETRY_NO_CLOCK: &str =
    "predecessor obligation has no durable first-observation time";
const APPROVAL_RETRY_NOT_RECEIVED: &str =
    "predecessor obligation not found — JoinRequestCreated not yet received";

#[derive(Debug)]
struct CapturedFrame {
    topic: String,
    sender: String,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
struct ApprovalReply {
    status: StatusCode,
    body: Value,
}

fn is_transient_approval_precondition(reply: &ApprovalReply) -> bool {
    reply.status == StatusCode::PRECONDITION_FAILED
        && reply.body["ok"] == false
        && matches!(
            reply.body["error"].as_str(),
            Some(error)
                if error == APPROVAL_RETRY_NO_CLOCK
                    || error == APPROVAL_RETRY_NOT_RECEIVED
        )
}

async fn retry_join_approval<F, Fut>(
    timeout: Duration,
    max_attempts: u32,
    retry_interval: Duration,
    mut attempt: F,
) -> Result<ApprovalReply, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ApprovalReply>,
{
    if max_attempts == 0 {
        return Err("approval retry attempt cap must be positive".to_string());
    }
    let deadline = tokio::time::Instant::now() + timeout;
    for attempt_number in 1..=max_attempts {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "approval retry deadline elapsed before attempt {attempt_number}"
            ));
        }
        let reply = tokio::time::timeout_at(deadline, attempt())
            .await
            .map_err(|_| {
                format!("approval retry deadline elapsed during attempt {attempt_number}")
            })?;
        if reply.status == StatusCode::OK {
            if reply.body["ok"] != true || reply.body["revision"].as_u64().is_none() {
                return Err(format!(
                    "malformed successful approval response on attempt {attempt_number}: {:?}",
                    reply.body
                ));
            }
            return Ok(reply);
        }
        if !is_transient_approval_precondition(&reply) {
            return Err(format!(
                "non-transient approval response on attempt {attempt_number}: status={} body={:?}",
                reply.status, reply.body
            ));
        }
        if attempt_number == max_attempts {
            return Err(format!(
                "approval retry exhausted {max_attempts} attempts: {:?}",
                reply.body
            ));
        }
        let now = tokio::time::Instant::now();
        if now >= deadline || retry_interval > deadline.saturating_duration_since(now) {
            return Err(format!(
                "approval retry deadline elapsed after {attempt_number} attempts: {:?}",
                reply.body
            ));
        }
        tokio::time::sleep(retry_interval).await;
    }
    unreachable!("positive bounded attempt loop must return")
}

fn verify_sse_observer_logs(
    stdout: std::io::Result<String>,
    stderr: std::io::Result<String>,
) -> Result<(), String> {
    let stdout = stdout.map_err(|error| format!("observer stdout log unavailable: {error}"))?;
    let stderr = stderr.map_err(|error| format!("observer stderr log unavailable: {error}"))?;
    if stdout.contains(SSE_LAG_MARKER) || stderr.contains(SSE_LAG_MARKER) {
        return Err("observer daemon reported SSE broadcast loss".to_string());
    }
    Ok(())
}

fn assert_sse_observer_did_not_lag(observer: &AgentInstance) {
    verify_sse_observer_logs(
        std::fs::read_to_string(observer.data_dir().join("daemon.stdout.log")),
        std::fs::read_to_string(observer.data_dir().join("daemon.stderr.log")),
    )
    .unwrap_or_else(|error| panic!("capture completeness guard failed: {error}"));
}

fn authed_client(d: &AgentInstance) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", d.api_token))
            .expect("auth header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(20))
        .build()
        .expect("authed client")
}

async fn json(d: &AgentInstance, method: reqwest::Method, path: &str, body: Value) -> Value {
    let response = authed_client(d)
        .request(method, d.url(path))
        .json(&body)
        .send()
        .await
        .expect("API request");
    let status = response.status();
    let value: Value = response.json().await.expect("API JSON response");
    assert!(status.is_success(), "{path} returned {status}: {value:?}");
    value
}

async fn wait_until<F, Fut>(mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + PHASE_TIMEOUT;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn bootstrap_cards(nodes: &[&AgentInstance]) {
    let mut cards = Vec::with_capacity(nodes.len());
    for node in nodes {
        cards.push(
            json(
                node,
                reqwest::Method::GET,
                "/agent/card?include_local_addresses=true",
                Value::Null,
            )
            .await["link"]
                .as_str()
                .expect("agent card link")
                .to_string(),
        );
    }
    for (dst, node) in nodes.iter().enumerate() {
        for (src, card) in cards.iter().enumerate() {
            if src != dst {
                let imported = json(
                    node,
                    reqwest::Method::POST,
                    "/agent/card/import",
                    serde_json::json!({"card": card, "trust_level": "Trusted"}),
                )
                .await;
                assert_eq!(imported["ok"], true);
            }
        }
    }
}

async fn admit(
    owner: &AgentInstance,
    joiner: &AgentInstance,
    owner_group: &str,
    remote_group: &str,
    joiner_id: &str,
) {
    let submitted = json(
        joiner,
        reqwest::Method::POST,
        &format!("/groups/{remote_group}/requests"),
        serde_json::json!({"message": "encrypted transport acceptance"}),
    )
    .await;
    let request_id = submitted["request_id"]
        .as_str()
        .expect("request id")
        .to_string();
    assert!(
        wait_until(|| async {
            let listed = json(
                owner,
                reqwest::Method::GET,
                &format!("/groups/{owner_group}/requests"),
                Value::Null,
            )
            .await;
            listed["requests"].as_array().is_some_and(|items| {
                items.iter().any(|item| {
                    item["request_id"].as_str() == Some(request_id.as_str())
                        && item["requester_agent_id"].as_str() == Some(joiner_id)
                        && item["status"].as_str() == Some("pending")
                })
            })
        })
        .await,
        "owner never observed join request from {joiner_id}"
    );
    let approval_path = format!("/groups/{owner_group}/requests/{request_id}/approve");
    let approved = retry_join_approval(
        PHASE_TIMEOUT,
        APPROVAL_RETRY_MAX_ATTEMPTS,
        APPROVAL_RETRY_INTERVAL,
        || async {
            let response = authed_client(owner)
                .post(owner.url(&approval_path))
                .json(&serde_json::json!({}))
                .send()
                .await
                .expect("approve join request");
            let status = response.status();
            let body = response.json().await.expect("approve join JSON response");
            ApprovalReply { status, body }
        },
    )
    .await
    .unwrap_or_else(|error| panic!("join approval did not complete: {error}"));
    assert_eq!(approved.body["ok"], true);
}

async fn open_store(d: &AgentInstance, group: &str) -> Value {
    let deadline = tokio::time::Instant::now() + PHASE_TIMEOUT;
    loop {
        let response = authed_client(d)
            .post(d.url(&format!("/groups/{group}/stores")))
            .json(&serde_json::json!({"name": "transport-proof"}))
            .send()
            .await
            .expect("open store request");
        let status = response.status();
        let value: Value = response.json().await.expect("open store JSON");
        let ready = status.is_success() && value["policy"] == "encrypted";
        if ready {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "encrypted group store never opened: status={status}, body={value:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn subscribe(d: &AgentInstance, topic: &str) -> String {
    let response = json(
        d,
        reqwest::Method::POST,
        "/subscribe",
        serde_json::json!({"topic": topic}),
    )
    .await;
    assert_eq!(response["ok"], true);
    response["subscription_id"]
        .as_str()
        .expect("subscription id")
        .to_string()
}

async fn unsubscribe(d: &AgentInstance, id: &str) {
    let response = authed_client(d)
        .delete(d.url(&format!("/subscribe/{id}")))
        .send()
        .await
        .expect("unsubscribe request");
    assert_eq!(response.status(), StatusCode::OK);
}

async fn start_sse_reader(d: &AgentInstance) -> mpsc::Receiver<Result<CapturedFrame, String>> {
    let session = d.session_token().await;
    let response = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("SSE client")
        .get(d.url(&format!("/events?token={session}")))
        .send()
        .await
        .expect("open SSE stream");
    assert_eq!(response.status(), StatusCode::OK);
    let (tx, rx) = mpsc::channel(128);
    tokio::spawn(async move {
        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    let _ = tx.send(Err(format!("SSE read failed: {error}"))).await;
                    return;
                }
            };
            buffer.extend_from_slice(&chunk);
            while let Some((end, delimiter_len)) = buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|end| (end, 4))
                .or_else(|| {
                    buffer
                        .windows(2)
                        .position(|window| window == b"\n\n")
                        .map(|end| (end, 2))
                })
            {
                let frame: Vec<u8> = buffer.drain(..end + delimiter_len).collect();
                let text = match std::str::from_utf8(&frame) {
                    Ok(text) => text.replace("\r\n", "\n"),
                    Err(error) => {
                        let _ = tx
                            .send(Err(format!("SSE frame was not UTF-8: {error}")))
                            .await;
                        return;
                    }
                };
                let Some(data) = text
                    .lines()
                    .find_map(|line| line.strip_prefix("data:").map(str::trim_start))
                else {
                    continue;
                };
                let event: Value = match serde_json::from_str(data) {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = tx
                            .send(Err(format!("SSE data was not JSON: {error}")))
                            .await;
                        return;
                    }
                };
                if event["type"] != "message" {
                    continue;
                }
                let Some(topic) = event["data"]["topic"].as_str() else {
                    let _ = tx
                        .send(Err("message event omitted topic".to_string()))
                        .await;
                    return;
                };
                let Some(sender) = event["data"]["sender"].as_str() else {
                    let _ = tx
                        .send(Err("message event omitted verified sender".to_string()))
                        .await;
                    return;
                };
                if event["data"]["verified"] != true {
                    let _ = tx
                        .send(Err("message event was not verified".to_string()))
                        .await;
                    return;
                }
                let Some(encoded) = event["data"]["payload"].as_str() else {
                    let _ = tx
                        .send(Err("message event omitted payload".to_string()))
                        .await;
                    return;
                };
                let payload = match BASE64.decode(encoded) {
                    Ok(payload) => payload,
                    Err(error) => {
                        let _ = tx
                            .send(Err(format!("message payload was not base64: {error}")))
                            .await;
                        return;
                    }
                };
                if tx
                    .send(Ok(CapturedFrame {
                        topic: topic.to_string(),
                        sender: sender.to_string(),
                        payload,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        if !buffer.is_empty() {
            let _ = tx
                .send(Err("SSE ended with a partial frame".to_string()))
                .await;
        } else {
            let _ = tx
                .send(Err("SSE ended before the fixture completed".to_string()))
                .await;
        }
    });
    rx
}

fn decode_envelope(payload: &[u8]) -> Result<EncryptedKvStoreRecordV1, String> {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(16 * 1024 * 1024)
        .deserialize::<(PeerId, EncryptedKvStoreRecordV1)>(payload)
        .map(|(_, record)| record)
        .map_err(|error| format!("not an encrypted KV envelope: {error}"))
}

fn validate_frame(
    frame: &CapturedFrame,
    topic: &str,
    sender: &str,
    group_id: &[u8],
    store_id: &[u8; 32],
    minimum_epoch: u64,
    forbidden: &[&[u8]],
) -> Result<EncryptedKvStoreRecordV1, String> {
    if frame.topic != topic {
        return Err("unrelated topic".to_string());
    }
    if frame.sender != sender {
        return Err("unrelated sender".to_string());
    }
    for bytes in forbidden {
        if !bytes.is_empty()
            && frame
                .payload
                .windows(bytes.len())
                .any(|window| window == *bytes)
        {
            return Err("recognizable plaintext in transport payload".to_string());
        }
    }
    let record = decode_envelope(&frame.payload)?;
    if record.group_id != group_id {
        return Err("wrong group binding".to_string());
    }
    if &record.store_id != store_id {
        return Err("wrong store binding".to_string());
    }
    if record.epoch < minimum_epoch {
        return Err("old epoch".to_string());
    }
    if record.ciphertext.len() <= 16 {
        return Err("missing authenticated ciphertext".to_string());
    }
    Ok(record)
}

async fn next_phase_frame(
    rx: &mut mpsc::Receiver<Result<CapturedFrame, String>>,
    topic: &str,
    sender: &str,
    group_id: &[u8],
    store_id: &[u8; 32],
    minimum_epoch: u64,
    forbidden: &[&[u8]],
) -> EncryptedKvStoreRecordV1 {
    tokio::time::timeout(PHASE_TIMEOUT, async {
        loop {
            let frame = rx
                .recv()
                .await
                .expect("SSE reader stopped")
                .expect("SSE parser");
            if frame.topic != topic || frame.sender != sender {
                continue;
            }
            return validate_frame(
                &frame,
                topic,
                sender,
                group_id,
                store_id,
                minimum_epoch,
                forbidden,
            )
            .unwrap_or_else(|error| panic!("relevant transport frame rejected: {error}"));
        }
    })
    .await
    .expect("timed out waiting for exact encrypted transport frame")
}

fn drain_phase(rx: &mut mpsc::Receiver<Result<CapturedFrame, String>>) {
    while let Ok(item) = rx.try_recv() {
        item.expect("SSE parser before phase");
    }
}

#[allow(clippy::too_many_arguments)]
async fn validate_phase_tail(
    rx: &mut mpsc::Receiver<Result<CapturedFrame, String>>,
    topic: &str,
    sender: &str,
    group_id: &[u8],
    store_id: &[u8; 32],
    minimum_epoch: u64,
    forbidden: &[&[u8]],
) {
    // The phase already has a required exact frame and a positive remote-state
    // barrier. This short quiet window is only to inspect delayed duplicates:
    // every additional frame from the same sender on the same transport topic
    // must satisfy the identical sealed-envelope oracle.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining.min(Duration::from_millis(200)), rx.recv()).await {
            Ok(Some(Ok(frame))) if frame.topic == topic && frame.sender == sender => {
                validate_frame(
                    &frame,
                    topic,
                    sender,
                    group_id,
                    store_id,
                    minimum_epoch,
                    forbidden,
                )
                .unwrap_or_else(|error| panic!("delayed relevant frame rejected: {error}"));
            }
            Ok(Some(Ok(_))) | Err(_) => {}
            Ok(Some(Err(error))) => panic!("SSE parser: {error}"),
            Ok(None) => panic!("SSE reader stopped during phase"),
        }
    }
}

fn store_value_url(d: &AgentInstance, topic: &str, key: &str) -> reqwest::Url {
    let mut url = reqwest::Url::parse(&d.url("/")).expect("daemon base URL");
    url.path_segments_mut()
        .expect("daemon URL supports path segments")
        .extend(["stores", topic, key]);
    url
}

async fn put(d: &AgentInstance, topic: &str, key: &str, value: &[u8]) {
    let url = store_value_url(d, topic, key);
    let response = json(
        d,
        reqwest::Method::PUT,
        url.path(),
        serde_json::json!({"value": BASE64.encode(value), "content_type": "application/octet-stream"}),
    )
    .await;
    assert_eq!(response["ok"], true);
}

async fn reads(d: &AgentInstance, topic: &str, key: &str, expected: &[u8]) -> bool {
    let response = authed_client(d)
        .get(store_value_url(d, topic, key))
        .send()
        .await
        .expect("read store request");
    if !response.status().is_success() {
        return false;
    }
    let value: Value = response.json().await.expect("read store JSON");
    value["value"]
        .as_str()
        .and_then(|encoded| BASE64.decode(encoded).ok())
        .is_some_and(|bytes| bytes == expected)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn encrypted_kv_leave_rekey_restart_has_only_sealed_transport_payloads() {
    let mut trio = trio_with_extra_config("").await;
    bootstrap_cards(&[&trio.alice, &trio.bob, &trio.charlie]).await;
    let alice_id = trio.alice.agent_id().await;
    let bob_id = trio.bob.agent_id().await;
    let charlie_id = trio.charlie.agent_id().await;

    let created = json(
        &trio.alice,
        reqwest::Method::POST,
        "/groups",
        serde_json::json!({"name": "encrypted-transport-proof", "preset": "public_request_secure"}),
    )
    .await;
    let owner_group = created["group_id"].as_str().expect("group id").to_string();
    let card = json(
        &trio.alice,
        reqwest::Method::GET,
        &format!("/groups/cards/{owner_group}"),
        Value::Null,
    )
    .await;
    let remote_group = card["group_id"]
        .as_str()
        .unwrap_or(&owner_group)
        .to_string();
    for node in [&trio.bob, &trio.charlie] {
        let imported = json(
            node,
            reqwest::Method::POST,
            "/groups/cards/import",
            card.clone(),
        )
        .await;
        assert_eq!(imported["ok"], true);
    }
    admit(&trio.alice, &trio.bob, &owner_group, &remote_group, &bob_id).await;
    admit(
        &trio.alice,
        &trio.charlie,
        &owner_group,
        &remote_group,
        &charlie_id,
    )
    .await;

    let owner_store = open_store(&trio.alice, &owner_group).await;
    let bob_store = open_store(&trio.bob, &remote_group).await;
    let charlie_store = open_store(&trio.charlie, &remote_group).await;
    let topic = owner_store["topic"]
        .as_str()
        .expect("store topic")
        .to_string();
    assert_eq!(bob_store["topic"], topic);
    assert_eq!(charlie_store["topic"], topic);
    let group_bytes = owner_store["group_id"]
        .as_str()
        .expect("stable group id")
        .as_bytes()
        .to_vec();
    let store_vec =
        hex::decode(owner_store["store_id"].as_str().expect("store id")).expect("store id hex");
    let store_id: [u8; 32] = store_vec.try_into().expect("32-byte store id");
    let initial_epoch = owner_store["epoch"].as_u64().expect("store epoch");
    let side_topic = format!("{topic}/state-sync");

    let mut main_sub = subscribe(&trio.charlie, &topic).await;
    let mut side_sub = subscribe(&trio.charlie, &side_topic).await;
    let mut captures = start_sse_reader(&trio.charlie).await;
    drain_phase(&mut captures);

    let pre_key = format!("pre-{}", rand::random::<u64>());
    let pre_value = format!("pre-value-{}", rand::random::<u64>()).into_bytes();
    let pre_value_b64 = BASE64.encode(&pre_value);
    put(&trio.alice, &topic, &pre_key, &pre_value).await;
    let pre = next_phase_frame(
        &mut captures,
        &topic,
        &alice_id,
        &group_bytes,
        &store_id,
        initial_epoch,
        &[pre_key.as_bytes(), &pre_value, pre_value_b64.as_bytes()],
    )
    .await;
    assert!(wait_until(|| reads(&trio.bob, &topic, &pre_key, &pre_value)).await);
    validate_phase_tail(
        &mut captures,
        &topic,
        &alice_id,
        &group_bytes,
        &store_id,
        initial_epoch,
        &[pre_key.as_bytes(), &pre_value, pre_value_b64.as_bytes()],
    )
    .await;

    let removed = authed_client(&trio.alice)
        .delete(
            trio.alice
                .url(&format!("/groups/{owner_group}/members/{charlie_id}")),
        )
        .send()
        .await
        .expect("remove member request");
    assert_eq!(removed.status(), StatusCode::OK);

    // The group-store sync retirement unsubscribes its own main and side-topic
    // handles. Recreate the independent raw subscriptions after removal and
    // prove their API ownership explicitly rather than assuming refcounts.
    unsubscribe(&trio.charlie, &main_sub).await;
    unsubscribe(&trio.charlie, &side_sub).await;
    main_sub = subscribe(&trio.charlie, &topic).await;
    side_sub = subscribe(&trio.charlie, &side_topic).await;
    drain_phase(&mut captures);

    let post_store = open_store(&trio.alice, &owner_group).await;
    let post_epoch = post_store["epoch"].as_u64().expect("post-remove epoch");
    assert!(
        post_epoch > pre.epoch,
        "member removal did not rekey the store"
    );
    let post_key = format!("post-{}", rand::random::<u64>());
    let post_value = format!("post-value-{}", rand::random::<u64>()).into_bytes();
    let post_value_b64 = BASE64.encode(&post_value);
    put(&trio.alice, &topic, &post_key, &post_value).await;
    let post = next_phase_frame(
        &mut captures,
        &topic,
        &alice_id,
        &group_bytes,
        &store_id,
        post_epoch,
        &[post_key.as_bytes(), &post_value, post_value_b64.as_bytes()],
    )
    .await;
    assert_eq!(post.epoch, post_epoch);
    assert!(wait_until(|| reads(&trio.bob, &topic, &post_key, &post_value)).await);
    validate_phase_tail(
        &mut captures,
        &topic,
        &alice_id,
        &group_bytes,
        &store_id,
        post_epoch,
        &[post_key.as_bytes(), &post_value, post_value_b64.as_bytes()],
    )
    .await;

    drain_phase(&mut captures);
    trio.bob.restart().await;
    let reopened = open_store(&trio.bob, &remote_group).await;
    assert_eq!(reopened["topic"], topic);

    // Reopening starts the request loop. Observe B's sealed control request
    // and A's sealed retained response on distinct transport topics.
    let control = next_phase_frame(
        &mut captures,
        &side_topic,
        &bob_id,
        &group_bytes,
        &store_id,
        post_epoch,
        &[
            pre_key.as_bytes(),
            &pre_value,
            post_key.as_bytes(),
            &post_value,
        ],
    )
    .await;
    assert!(control.epoch >= post_epoch);
    let retained = next_phase_frame(
        &mut captures,
        &topic,
        &alice_id,
        &group_bytes,
        &store_id,
        post_epoch,
        &[
            pre_key.as_bytes(),
            &pre_value,
            post_key.as_bytes(),
            &post_value,
        ],
    )
    .await;
    assert!(retained.epoch >= post_epoch);
    assert!(wait_until(|| reads(&trio.bob, &topic, &post_key, &post_value)).await);
    validate_phase_tail(
        &mut captures,
        &topic,
        &alice_id,
        &group_bytes,
        &store_id,
        post_epoch,
        &[
            pre_key.as_bytes(),
            &pre_value,
            post_key.as_bytes(),
            &post_value,
        ],
    )
    .await;

    let restart_key = format!("restart-{}", rand::random::<u64>());
    let restart_value = format!("restart-value-{}", rand::random::<u64>()).into_bytes();
    let restart_value_b64 = BASE64.encode(&restart_value);
    drain_phase(&mut captures);
    put(&trio.bob, &topic, &restart_key, &restart_value).await;
    let restarted = next_phase_frame(
        &mut captures,
        &topic,
        &bob_id,
        &group_bytes,
        &store_id,
        post_epoch,
        &[
            restart_key.as_bytes(),
            &restart_value,
            restart_value_b64.as_bytes(),
        ],
    )
    .await;
    assert!(restarted.epoch >= post_epoch);
    assert!(wait_until(|| reads(&trio.alice, &topic, &restart_key, &restart_value)).await);
    validate_phase_tail(
        &mut captures,
        &topic,
        &bob_id,
        &group_bytes,
        &store_id,
        post_epoch,
        &[
            restart_key.as_bytes(),
            &restart_value,
            restart_value_b64.as_bytes(),
        ],
    )
    .await;

    unsubscribe(&trio.charlie, &main_sub).await;
    unsubscribe(&trio.charlie, &side_sub).await;
    // The server resumes silently after a broadcast receiver lag and exposes
    // that loss only through its owned warning logs. Both sinks must exist and
    // remain marker-free before this run can claim no server-reported capture
    // gap. This is bounded to the daemon's defined lag signal; it is not a
    // claim about transport paths the fixture did not exercise.
    assert_sse_observer_did_not_lag(&trio.charlie);
}

#[test]
fn frame_oracle_rejects_plaintext_tampering_unrelated_and_old_epoch() {
    let topic = "x0x/group/g/kv/proof";
    let sender = "11".repeat(32);
    let group = b"stable-group".to_vec();
    let store = [7; 32];
    let record = EncryptedKvStoreRecordV1 {
        group_id: group.clone(),
        store_id: store,
        epoch: 9,
        nonce: [3; 24],
        ciphertext: vec![0xA5; 64],
    };
    let payload = bincode::options()
        .with_fixint_encoding()
        .serialize(&(PeerId::new([1; 32]), record))
        .expect("fixture envelope");
    let valid = CapturedFrame {
        topic: topic.to_string(),
        sender: sender.clone(),
        payload,
    };
    assert!(validate_frame(&valid, topic, &sender, &group, &store, 9, &[b"secret"]).is_ok());

    let plaintext = CapturedFrame {
        payload: b"secret".to_vec(),
        ..CapturedFrame {
            topic: valid.topic.clone(),
            sender: valid.sender.clone(),
            payload: valid.payload.clone(),
        }
    };
    assert!(validate_frame(&plaintext, topic, &sender, &group, &store, 9, &[b"secret"]).is_err());
    assert!(validate_frame(&valid, "other", &sender, &group, &store, 9, &[]).is_err());
    assert!(validate_frame(&valid, topic, &sender, b"tampered-group", &store, 9, &[]).is_err());
    assert!(validate_frame(&valid, topic, &sender, &group, &[8; 32], 9, &[]).is_err());
    assert!(validate_frame(&valid, topic, &sender, &group, &store, 10, &[]).is_err());
}

#[test]
fn sse_log_guard_accepts_clean_logs_and_rejects_lag_or_missing_sink() {
    assert!(verify_sse_observer_logs(
        Ok("ordinary observer output\n".to_string()),
        Ok("ordinary observer warning\n".to_string()),
    )
    .is_ok());
    assert!(
        verify_sse_observer_logs(Ok(format!("WARN {SSE_LAG_MARKER}\n")), Ok(String::new()),)
            .is_err()
    );
    assert!(
        verify_sse_observer_logs(Ok(String::new()), Ok(format!("WARN {SSE_LAG_MARKER}\n")),)
            .is_err()
    );
    assert!(verify_sse_observer_logs(
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing stdout",
        )),
        Ok(String::new()),
    )
    .is_err());
}

#[tokio::test]
async fn join_approval_retry_accepts_only_exact_transient_then_success() {
    let mut replies = std::collections::VecDeque::from([
        ApprovalReply {
            status: StatusCode::PRECONDITION_FAILED,
            body: serde_json::json!({"ok": false, "error": APPROVAL_RETRY_NOT_RECEIVED}),
        },
        ApprovalReply {
            status: StatusCode::PRECONDITION_FAILED,
            body: serde_json::json!({"ok": false, "error": APPROVAL_RETRY_NO_CLOCK}),
        },
        ApprovalReply {
            status: StatusCode::OK,
            body: serde_json::json!({"ok": true, "revision": 9}),
        },
    ]);
    let reply = retry_join_approval(Duration::from_secs(1), 3, Duration::ZERO, || {
        let reply = replies.pop_front().expect("scripted approval response");
        async move { reply }
    })
    .await
    .expect("exact transient responses may reach success");
    assert_eq!(reply.body["revision"], 9);
    assert!(replies.is_empty());
}

#[tokio::test]
async fn join_approval_retry_rejects_permanent_fatal_and_malformed_responses() {
    for reply in [
        ApprovalReply {
            status: StatusCode::PRECONDITION_FAILED,
            body: serde_json::json!({"ok": false, "error": "predecessor obligation expired"}),
        },
        ApprovalReply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: serde_json::json!({"ok": false, "error": APPROVAL_RETRY_NOT_RECEIVED}),
        },
        ApprovalReply {
            status: StatusCode::OK,
            body: serde_json::json!({"ok": false}),
        },
        ApprovalReply {
            status: StatusCode::OK,
            body: serde_json::json!({"ok": true}),
        },
    ] {
        let result = retry_join_approval(Duration::from_secs(1), 2, Duration::ZERO, || {
            let reply = reply.clone();
            async move { reply }
        })
        .await;
        assert!(result.is_err(), "unexpected approval response must fail");
    }
}

#[tokio::test]
async fn join_approval_retry_exhaustion_cannot_mask_permanent_absence() {
    let mut attempts = 0;
    let result = retry_join_approval(Duration::from_secs(1), 3, Duration::ZERO, || {
        attempts += 1;
        async {
            ApprovalReply {
                status: StatusCode::PRECONDITION_FAILED,
                body: serde_json::json!({"ok": false, "error": APPROVAL_RETRY_NOT_RECEIVED}),
            }
        }
    })
    .await;
    assert!(result
        .expect_err("permanent transient response must exhaust")
        .contains("exhausted 3 attempts"));
    assert_eq!(attempts, 3);
}

#[tokio::test]
async fn join_approval_retry_deadline_bounds_a_pending_attempt() {
    let result = retry_join_approval(Duration::from_millis(10), 3, Duration::ZERO, || async {
        std::future::pending::<ApprovalReply>().await
    })
    .await;
    assert!(result
        .expect_err("pending approval request must hit the total deadline")
        .contains("deadline elapsed during attempt 1"));
}
