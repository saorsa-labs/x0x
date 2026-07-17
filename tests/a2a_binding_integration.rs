//! Integration tests for the A2A-over-x0x binding (issue #112, increment 1).
//!
//! Two in-process agents exchange A2A unary JSON-RPC calls over the real
//! DM path (loopback QUIC, `RawQuicAcked`-preferred):
//!
//! - round-trip success for `message/send`, `tasks/get`, `tasks/cancel`
//! - unknown method → JSON-RPC `-32601` error
//! - request timeout fires and the in-flight map is cleaned up
//! - concurrent interleaving keeps `corrId` correlation intact

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use x0x::a2a::binding::{
    BindingConfig, BindingError, BindingSession, JsonRpcError, JSONRPC_METHOD_NOT_FOUND,
};
use x0x::network::NetworkConfig;
use x0x::{Agent, DiscoveredAgent};
use serde_json::Value;

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

fn normalize_loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    if addr.ip().is_unspecified() {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )
    } else {
        addr
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("All socket binds failed")
            || message.contains("Failed to bind UDP socket")
            || message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

fn discovered_agent(agent: &Agent, addr: std::net::SocketAddr, now_secs: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: None,
        addresses: vec![addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: vec![],
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

/// Helper to create a loopback-only test agent with isolated storage.
async fn create_loopback_test_agent(
    temp_dir: &TempDir,
    name: &str,
) -> Result<Option<Agent>, Box<dyn std::error::Error>> {
    let machine_key_path = temp_dir.path().join(format!("{name}_machine.key"));
    let agent_key_path = temp_dir.path().join(format!("{name}_agent.key"));
    let contacts_path = temp_dir.path().join(format!("{name}_contacts.json"));

    match Agent::builder()
        .with_machine_key(machine_key_path)
        .with_agent_key_path(agent_key_path)
        .with_contact_store_path(contacts_path)
        .with_peer_cache_disabled()
        .with_network_config(loopback_network_config())
        .build()
        .await
    {
        Ok(agent) => Ok(Some(agent)),
        Err(error) if is_network_bind_permission_error(&error) => Ok(None),
        Err(error) => Err(Box::new(error)),
    }
}

struct BindingPair {
    bob_id: x0x::identity::AgentId,
    alice_session: Arc<BindingSession>,
    bob_session: Arc<BindingSession>,
}

/// Bring up two loopback agents on the real DM path, each with a binding
/// session. Returns `None` when the sandbox forbids UDP binds (same skip
/// convention as the DM integration tests).
async fn setup_pair(
    temp_dir: &TempDir,
    alice_request_timeout: Duration,
) -> Result<Option<BindingPair>, Box<dyn std::error::Error>> {
    let Some(alice) = create_loopback_test_agent(temp_dir, "alice").await? else {
        return Ok(None);
    };
    let Some(bob) = create_loopback_test_agent(temp_dir, "bob").await? else {
        return Ok(None);
    };

    alice.join_network().await?;
    bob.join_network().await?;

    let alice = Arc::new(alice);
    let bob = Arc::new(bob);

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.expect("alice bound"));
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let alice_peer = ant_quic::PeerId(alice.machine_id().0);
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    let connected = alice_network.connect_addr(bob_addr).await?;
    assert_eq!(connected.0, bob.machine_id().0);

    // The binding is bidirectional (requests alice→bob, responses bob→alice),
    // so wait for BOTH directions of the QUIC connection to be visible.
    let connected_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < connected_deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network.is_connected(&alice_peer).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(alice_network.is_connected(&bob_peer).await);
    assert!(bob_network.is_connected(&alice_peer).await);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    alice
        .direct_messaging()
        .mark_connected(bob.agent_id(), bob.machine_id())
        .await;
    bob.direct_messaging()
        .mark_connected(alice.agent_id(), alice.machine_id())
        .await;

    let alice_config = BindingConfig {
        request_timeout: alice_request_timeout,
        ..BindingConfig::default()
    };
    let alice_session = Arc::new(BindingSession::start(Arc::clone(&alice), alice_config));
    let bob_session = Arc::new(BindingSession::start(
        Arc::clone(&bob),
        BindingConfig::default(),
    ));

    Ok(Some(BindingPair {
        bob_id: bob.agent_id(),
        alice_session,
        bob_session,
    }))
}

/// Register the three A2A unary methods of this increment with canned,
/// A2A-shaped responses that echo identifying bits of the params so tests
/// can verify correlation.
fn register_a2a_handlers(session: &BindingSession) {
    session.register_handler("message/send", |params| async move {
        let text = params
            .as_ref()
            .and_then(|p| p.get("message"))
            .and_then(|m| m.get("parts"))
            .and_then(|parts| parts.get(0))
            .and_then(|part| part.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(serde_json::json!({
            "kind": "message",
            "messageId": format!("msg-{text}"),
            "role": "agent",
            "parts": [{"kind": "text", "text": format!("ack:{text}")}],
        }))
    });

    session.register_handler("tasks/get", |params| async move {
        let id = task_id(params.as_ref());
        Ok(serde_json::json!({
            "kind": "task",
            "id": id,
            "status": {"state": "completed", "timestamp": "2026-07-17T00:00:00Z"},
        }))
    });

    session.register_handler("tasks/cancel", |params| async move {
        let id = task_id(params.as_ref());
        Ok(serde_json::json!({
            "kind": "task",
            "id": id,
            "status": {"state": "canceled", "timestamp": "2026-07-17T00:00:00Z"},
        }))
    });
}

fn task_id(params: Option<&Value>) -> String {
    params
        .and_then(|p| p.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("task-unknown")
        .to_string()
}

fn message_send_params(text: &str) -> Value {
    serde_json::json!({
        "message": {
            "kind": "message",
            "messageId": format!("req-{text}"),
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
        }
    })
}

/// Round-trip: alice completes message/send + tasks/get + tasks/cancel
/// against bob over the real DM path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unary_round_trip_over_dm() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(pair) = setup_pair(&temp_dir, Duration::from_secs(30)).await? else {
        return Ok(());
    };
    register_a2a_handlers(&pair.bob_session);

    let message = pair
        .alice_session
        .call(
            &pair.bob_id,
            "message/send",
            Some(message_send_params("hello-a2a")),
        )
        .await?;
    assert_eq!(message["kind"], Value::String("message".to_string()));
    assert_eq!(message["role"], Value::String("agent".to_string()));
    assert_eq!(message["parts"][0]["text"], Value::String("ack:hello-a2a".to_string()));

    let task = pair
        .alice_session
        .call(
            &pair.bob_id,
            "tasks/get",
            Some(serde_json::json!({"id": "task-42"})),
        )
        .await?;
    assert_eq!(task["id"], Value::String("task-42".to_string()));
    assert_eq!(
        task["status"]["state"],
        Value::String("completed".to_string())
    );

    let cancelled = pair
        .alice_session
        .call(
            &pair.bob_id,
            "tasks/cancel",
            Some(serde_json::json!({"id": "task-42"})),
        )
        .await?;
    assert_eq!(cancelled["id"], Value::String("task-42".to_string()));
    assert_eq!(
        cancelled["status"]["state"],
        Value::String("canceled".to_string())
    );

    // Completed calls drain from the in-flight map.
    assert_eq!(pair.alice_session.in_flight_len(), 0);
    Ok(())
}

/// Unknown method: bob has no handler registered, so alice receives a
/// JSON-RPC `-32601` error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_method_returns_jsonrpc_error() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(pair) = setup_pair(&temp_dir, Duration::from_secs(30)).await? else {
        return Ok(());
    };
    register_a2a_handlers(&pair.bob_session);

    let err = pair
        .alice_session
        .call(&pair.bob_id, "message/stream", None)
        .await
        .expect_err("unregistered method must fail");
    match err {
        BindingError::Remote { code, message, .. } => {
            assert_eq!(code, JSONRPC_METHOD_NOT_FOUND);
            assert!(message.contains("message/stream"));
        }
        other => panic!("expected BindingError::Remote, got {other:?}"),
    }
    assert_eq!(pair.alice_session.in_flight_len(), 0);
    Ok(())
}

/// Timeout: bob's handler never answers; alice's call times out, the
/// in-flight entry is removed, and the session stays healthy for a
/// follow-up call (no cross-talk with the stalled request).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_timeout_fires_and_session_stays_healthy(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(pair) = setup_pair(&temp_dir, Duration::from_millis(500)).await? else {
        return Ok(());
    };
    register_a2a_handlers(&pair.bob_session);
    pair.bob_session.register_handler("work/stall", |_params| {
        std::future::pending::<Result<Value, JsonRpcError>>()
    });

    let started = Instant::now();
    let err = pair
        .alice_session
        .call(&pair.bob_id, "work/stall", None)
        .await
        .expect_err("stalled handler must time out");
    assert!(
        matches!(err, BindingError::Timeout(d) if d == Duration::from_millis(500)),
        "expected 500ms timeout, got {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "timeout should fire at the configured 500ms, not hang"
    );
    // Timed-out request is evicted from the in-flight map.
    assert_eq!(pair.alice_session.in_flight_len(), 0);

    // The stall handler occupies only its own task: a follow-up unary call
    // still round-trips.
    let message = pair
        .alice_session
        .call(&pair.bob_id, "message/send", Some(message_send_params("after-timeout")))
        .await?;
    assert_eq!(
        message["parts"][0]["text"],
        Value::String("ack:after-timeout".to_string())
    );
    Ok(())
}

/// Caller cancellation: the caller drops the `call` future mid-flight
/// (HTTP-client-disconnect shape) and the peer never responds — the
/// in-flight entry MUST be removed, not leaked for the session's life.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_call_future_cleans_in_flight_entry(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(pair) = setup_pair(&temp_dir, Duration::from_secs(30)).await? else {
        return Ok(());
    };
    pair.bob_session.register_handler("work/stall", |_params| {
        std::future::pending::<Result<Value, JsonRpcError>>()
    });

    let session = Arc::clone(&pair.alice_session);
    let bob_id = pair.bob_id;
    let handle = tokio::spawn(async move { session.call(&bob_id, "work/stall", None).await });

    // Wait until the request is registered in-flight.
    let deadline = Instant::now() + Duration::from_secs(5);
    while pair.alice_session.in_flight_len() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(pair.alice_session.in_flight_len(), 1);

    // Caller "disconnects": the call future is dropped while awaiting a
    // response that will never come.
    handle.abort();
    let join_err = handle.await.expect_err("aborted task must join as cancelled");
    assert!(join_err.is_cancelled());

    assert_eq!(
        pair.alice_session.in_flight_len(),
        0,
        "dropped call future must not leak its in-flight waiter"
    );
    Ok(())
}

/// Concurrent interleaving: many in-flight unary calls across all three A2A
/// methods (plus a delayed echo method) must each receive their own
/// correlated response — corrIds never cross.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_calls_do_not_cross_correlation() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(pair) = setup_pair(&temp_dir, Duration::from_secs(30)).await? else {
        return Ok(());
    };
    register_a2a_handlers(&pair.bob_session);
    pair.bob_session.register_handler("work/echo", |params| async move {
        let i = params
            .as_ref()
            .and_then(|p| p.get("i"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // Deterministic scatter so responses arrive out of order.
        tokio::time::sleep(Duration::from_millis(((i * 37) % 5) * 10)).await;
        Ok(serde_json::json!({"i": i, "echoed": true}))
    });

    let mut set = tokio::task::JoinSet::new();
    for lane in 0..4u64 {
        let session = Arc::clone(&pair.alice_session);
        let bob_id = pair.bob_id;
        set.spawn(async move {
            session
                .call(
                    &bob_id,
                    "message/send",
                    Some(message_send_params(&format!("lane-{lane}"))),
                )
                .await
                .map(|v| ("message/send".to_string(), lane, v))
        });
        let session = Arc::clone(&pair.alice_session);
        let bob_id = pair.bob_id;
        set.spawn(async move {
            session
                .call(
                    &bob_id,
                    "tasks/get",
                    Some(serde_json::json!({"id": format!("get-{lane}")})),
                )
                .await
                .map(|v| ("tasks/get".to_string(), lane, v))
        });
        let session = Arc::clone(&pair.alice_session);
        let bob_id = pair.bob_id;
        set.spawn(async move {
            session
                .call(
                    &bob_id,
                    "tasks/cancel",
                    Some(serde_json::json!({"id": format!("cancel-{lane}")})),
                )
                .await
                .map(|v| ("tasks/cancel".to_string(), lane, v))
        });
        let session = Arc::clone(&pair.alice_session);
        let bob_id = pair.bob_id;
        set.spawn(async move {
            session
                .call(&bob_id, "work/echo", Some(serde_json::json!({"i": lane})))
                .await
                .map(|v| ("work/echo".to_string(), lane, v))
        });
    }

    let mut completed = 0usize;
    while let Some(joined) = set.join_next().await {
        let (method, lane, value) = joined.expect("call task panicked")?;
        match method.as_str() {
            "message/send" => assert_eq!(
                value["parts"][0]["text"],
                Value::String(format!("ack:lane-{lane}"))
            ),
            "tasks/get" => {
                assert_eq!(value["id"], Value::String(format!("get-{lane}")));
                assert_eq!(
                    value["status"]["state"],
                    Value::String("completed".to_string())
                );
            }
            "tasks/cancel" => {
                assert_eq!(value["id"], Value::String(format!("cancel-{lane}")));
                assert_eq!(
                    value["status"]["state"],
                    Value::String("canceled".to_string())
                );
            }
            "work/echo" => assert_eq!(value["i"], Value::from(lane)),
            other => panic!("unexpected method {other}"),
        }
        completed += 1;
    }
    assert_eq!(completed, 16);
    assert_eq!(pair.alice_session.in_flight_len(), 0);
    Ok(())
}
