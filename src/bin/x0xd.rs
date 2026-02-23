//! x0xd — local agent daemon for the x0x gossip network.
//!
//! Runs a persistent x0x agent with a REST API for local control.
//! Designed to be started once and left running; external tools
//! (CLI, Fae, scripts) interact through the HTTP endpoints.
//!
//! ## Usage
//!
//! ```bash
//! x0xd                                  # default config
//! x0xd --config /path/to/config.toml    # custom config
//! x0xd --check                          # validate config and exit
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::CorsLayer;
use x0x::contacts::{ContactStore, TrustLevel};
use x0x::identity::AgentId;
use x0x::network::NetworkConfig;
use x0x::{Agent, Subscription, TaskListHandle};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Daemon configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonConfig {
    /// QUIC bind address for gossip (default 0.0.0.0:0 = random).
    #[serde(default = "default_bind_address")]
    bind_address: SocketAddr,

    /// HTTP API address (default 127.0.0.1:12700).
    #[serde(default = "default_api_address")]
    api_address: SocketAddr,

    /// Data directory for persistent storage.
    #[serde(default = "default_data_dir")]
    data_dir: PathBuf,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    log_level: String,

    /// Bootstrap peers to connect on startup.
    #[serde(default)]
    bootstrap_peers: Vec<SocketAddr>,
}

fn default_bind_address() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

fn default_api_address() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 12700))
}

fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("x0x"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/x0x"))
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            api_address: default_api_address(),
            data_dir: default_data_dir(),
            log_level: default_log_level(),
            bootstrap_peers: x0x::network::DEFAULT_BOOTSTRAP_PEERS
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// SSE event broadcast to connected clients.
#[derive(Debug, Clone, Serialize)]
struct SseEvent {
    /// Event type: "message", "peer:connected", "peer:disconnected".
    #[serde(rename = "type")]
    event_type: String,
    /// Event payload (JSON value).
    data: serde_json::Value,
}

/// Shared state accessible from all route handlers.
struct AppState {
    agent: Arc<Agent>,
    subscriptions: RwLock<HashMap<String, Subscription>>,
    task_lists: RwLock<HashMap<String, TaskListHandle>>,
    contacts: Arc<RwLock<ContactStore>>,
    start_time: Instant,
    broadcast_tx: broadcast::Sender<SseEvent>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// POST /publish request body.
#[derive(Debug, Deserialize)]
struct PublishRequest {
    topic: String,
    /// Base64-encoded payload.
    payload: String,
}

/// POST /subscribe request body.
#[derive(Debug, Deserialize)]
struct SubscribeRequest {
    topic: String,
}

/// POST /task-lists request body.
#[derive(Debug, Deserialize)]
struct CreateTaskListRequest {
    name: String,
    topic: String,
}

/// POST /task-lists/:id/tasks request body.
#[derive(Debug, Deserialize)]
struct AddTaskRequest {
    title: String,
    description: String,
}

/// PATCH /task-lists/:id/tasks/:tid request body.
#[derive(Debug, Deserialize)]
struct UpdateTaskRequest {
    action: String, // "claim" or "complete"
}

/// POST /contacts request body.
#[derive(Debug, Deserialize)]
struct AddContactRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
    /// Trust level: "blocked", "unknown", "known", or "trusted".
    trust_level: String,
    /// Optional human-readable label.
    label: Option<String>,
}

/// PATCH /contacts/:agent_id request body.
#[derive(Debug, Deserialize)]
struct UpdateContactRequest {
    /// New trust level: "blocked", "unknown", "known", or "trusted".
    trust_level: String,
}

/// POST /contacts/trust request body (quick trust shorthand).
#[derive(Debug, Deserialize)]
struct QuickTrustRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
    /// Trust level: "blocked", "unknown", "known", or "trusted".
    level: String,
}

/// Contact entry for API responses.
#[derive(Debug, Serialize)]
struct ContactEntry {
    agent_id: String,
    trust_level: String,
    label: Option<String>,
    added_at: u64,
    last_seen: Option<u64>,
}

/// Generic JSON response wrapper.
#[derive(Debug, Serialize)]
struct ApiResponse<T: Serialize> {
    ok: bool,
    #[serde(flatten)]
    data: T,
}

/// Health response.
#[derive(Debug, Serialize)]
struct HealthData {
    status: String,
    version: String,
    peers: usize,
    uptime_secs: u64,
}

/// Agent identity response.
#[derive(Debug, Serialize)]
struct AgentData {
    agent_id: String,
    machine_id: String,
    user_id: Option<String>,
}

/// Peer entry.
#[derive(Debug, Serialize)]
struct PeerEntry {
    id: String,
}

/// Task list entry.
#[derive(Debug, Serialize)]
struct TaskListEntry {
    id: String,
    topic: String,
}

/// Task snapshot for API response.
#[derive(Debug, Serialize)]
struct TaskEntry {
    id: String,
    title: String,
    description: String,
    state: String,
    assignee: Option<String>,
    priority: u8,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let config_path = if let Some(idx) = args.iter().position(|a| a == "--config") {
        Some(
            args.get(idx + 1)
                .context("--config requires a path argument")?
                .clone(),
        )
    } else {
        None
    };

    let check_only = args.contains(&"--check".to_string());

    let config = match &config_path {
        Some(path) => load_config(path).await?,
        None => {
            // Try default path, fall back to default config
            let default_path = dirs::config_dir()
                .map(|d| d.join("x0x").join("config.toml"))
                .unwrap_or_else(|| PathBuf::from("/etc/x0x/config.toml"));
            if default_path.exists() {
                load_config(default_path.to_str().unwrap_or("/etc/x0x/config.toml")).await?
            } else {
                DaemonConfig::default()
            }
        }
    };

    init_logging(&config.log_level)?;

    if check_only {
        println!("Configuration is valid");
        println!("{:#?}", config);
        return Ok(());
    }

    tracing::info!("Starting x0xd v{}", x0x::VERSION);
    tracing::info!("API address: {}", config.api_address);
    tracing::info!("Bind address: {}", config.bind_address);

    // Ensure data directory exists
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .context("failed to create data directory")?;

    // Create agent
    let network_config = NetworkConfig {
        bind_addr: Some(config.bind_address),
        bootstrap_nodes: config.bootstrap_peers.clone(),
        max_connections: 50,
        connection_timeout: std::time::Duration::from_secs(30),
        stats_interval: std::time::Duration::from_secs(60),
        peer_cache_path: Some(config.data_dir.join("peers.cache")),
    };

    let agent = Agent::builder()
        .with_network_config(network_config)
        .build()
        .await
        .context("failed to create agent")?;

    tracing::info!("Agent ID: {}", agent.agent_id());
    tracing::info!("Machine ID: {}", agent.machine_id());

    // Create contact store and attach to gossip layer for trust filtering
    let contacts = Arc::new(RwLock::new(ContactStore::new(
        config.data_dir.join("contacts.json"),
    )));
    agent.set_contacts(Arc::clone(&contacts));
    tracing::info!(
        "Contact store loaded from {}",
        config.data_dir.join("contacts.json").display()
    );

    // Join network
    agent
        .join_network()
        .await
        .context("failed to join network")?;

    tracing::info!("Network joined");

    // Build shared state
    let (broadcast_tx, _) = broadcast::channel::<SseEvent>(256);
    let state = Arc::new(AppState {
        agent: Arc::new(agent),
        subscriptions: RwLock::new(HashMap::new()),
        task_lists: RwLock::new(HashMap::new()),
        contacts,
        start_time: Instant::now(),
        broadcast_tx,
    });

    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/agent", get(agent_info))
        .route("/peers", get(peers))
        .route("/publish", post(publish))
        .route("/subscribe", post(subscribe))
        .route("/subscribe/:id", delete(unsubscribe))
        .route("/events", get(events_sse))
        .route("/presence", get(presence))
        .route("/contacts", get(list_contacts))
        .route("/contacts", post(add_contact))
        .route("/contacts/trust", post(quick_trust))
        .route("/contacts/:agent_id", patch(update_contact))
        .route("/contacts/:agent_id", delete(delete_contact))
        .route("/task-lists", get(list_task_lists))
        .route("/task-lists", post(create_task_list))
        .route("/task-lists/:id/tasks", get(list_tasks))
        .route("/task-lists/:id/tasks", post(add_task))
        .route("/task-lists/:id/tasks/:tid", patch(update_task))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(config.api_address)
        .await
        .context("failed to bind API address")?;
    tracing::info!("API server listening on {}", config.api_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("API server error")?;

    tracing::info!("Shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    tracing::info!("Received shutdown signal");
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// GET /health
async fn health(State(state): State<Arc<AppState>>) -> Json<ApiResponse<HealthData>> {
    let peers = state.agent.peers().await.map(|p| p.len()).unwrap_or(0);

    Json(ApiResponse {
        ok: true,
        data: HealthData {
            status: "healthy".to_string(),
            version: x0x::VERSION.to_string(),
            peers,
            uptime_secs: state.start_time.elapsed().as_secs(),
        },
    })
}

/// GET /agent
async fn agent_info(State(state): State<Arc<AppState>>) -> Json<ApiResponse<AgentData>> {
    Json(ApiResponse {
        ok: true,
        data: AgentData {
            agent_id: format!("{}", state.agent.agent_id()),
            machine_id: format!("{}", state.agent.machine_id()),
            user_id: state.agent.user_id().map(|u| format!("{}", u)),
        },
    })
}

/// GET /peers
async fn peers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.peers().await {
        Ok(peer_list) => {
            let entries: Vec<PeerEntry> = peer_list
                .into_iter()
                .map(|p| PeerEntry {
                    id: hex::encode(p.to_bytes()),
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "peers": entries })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /publish
async fn publish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishRequest>,
) -> impl IntoResponse {
    // Decode base64 payload
    let payload = match base64::engine::general_purpose::STANDARD.decode(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid base64: {e}") })),
            );
        }
    };

    match state.agent.publish(&req.topic, payload).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /subscribe
async fn subscribe(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubscribeRequest>,
) -> impl IntoResponse {
    match state.agent.subscribe(&req.topic).await {
        Ok(sub) => {
            let id = format!("{:016x}", rand::random::<u64>());
            // Spawn background task to forward messages to SSE broadcast
            let broadcast_tx = state.broadcast_tx.clone();
            let topic = req.topic.clone();
            let mut recv_sub = sub;
            let sub_id = id.clone();
            tokio::spawn(async move {
                while let Some(msg) = recv_sub.recv().await {
                    let event = SseEvent {
                        event_type: "message".to_string(),
                        data: serde_json::json!({
                            "subscription_id": sub_id,
                            "topic": topic,
                            "payload": base64::engine::general_purpose::STANDARD.encode(&msg.payload),
                            "sender": msg.sender.map(|s| hex::encode(s.0)),
                            "verified": msg.verified,
                            "trust_level": msg.trust_level.map(|t| t.to_string()),
                        }),
                    };
                    let _ = broadcast_tx.send(event);
                }
            });

            // We've consumed the subscription in the spawned task;
            // store a placeholder subscription for unsubscribe tracking.
            // (The actual unsubscribe goes through PubSubManager::unsubscribe)
            let mut subs = state.subscriptions.write().await;
            // Create a new subscription for the unsubscribe path
            match state.agent.subscribe(&req.topic).await {
                Ok(new_sub) => {
                    subs.insert(id.clone(), new_sub);
                }
                Err(_) => {
                    // Non-fatal: the forwarding task is already running
                }
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "subscription_id": id })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// DELETE /subscribe/:id
async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut subs = state.subscriptions.write().await;
    if subs.remove(&id).is_some() {
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "subscription not found" })),
        )
    }
}

/// GET /events — Server-Sent Events stream.
async fn events_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.broadcast_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let data = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().event(event.event_type).data(data)))
        }
        Err(_) => None,
    });
    Sse::new(stream)
}

/// GET /presence
async fn presence(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.presence().await {
        Ok(agents) => {
            let entries: Vec<String> = agents.iter().map(|a| format!("{a}")).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Contact handlers
// ---------------------------------------------------------------------------

/// Parse a 64-character hex string into an AgentId.
fn parse_agent_id_hex(hex_str: &str) -> Result<AgentId, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(AgentId(arr))
}

/// GET /contacts — list all contacts with trust levels.
async fn list_contacts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let store = state.contacts.read().await;
    let entries: Vec<ContactEntry> = store
        .list()
        .into_iter()
        .map(|c| ContactEntry {
            agent_id: hex::encode(c.agent_id.0),
            trust_level: c.trust_level.to_string(),
            label: c.label.clone(),
            added_at: c.added_at,
            last_seen: c.last_seen,
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "contacts": entries }))
}

/// POST /contacts — add a new contact.
async fn add_contact(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddContactRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.trust_level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let contact = x0x::contacts::Contact {
        agent_id,
        trust_level,
        label: req.label,
        added_at: now,
        last_seen: None,
    };

    state.contacts.write().await.add(contact);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "agent_id": hex::encode(agent_id.0) })),
    )
}

/// PATCH /contacts/:agent_id — update trust level for a contact.
async fn update_contact(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Json(req): Json<UpdateContactRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.trust_level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    state
        .contacts
        .write()
        .await
        .set_trust(&agent_id, trust_level);

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// DELETE /contacts/:agent_id — remove a contact.
async fn delete_contact(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let removed = state.contacts.write().await.remove(&agent_id);
    if removed.is_some() {
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "contact not found" })),
        )
    }
}

/// POST /contacts/trust — quick trust shorthand.
async fn quick_trust(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QuickTrustRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    state
        .contacts
        .write()
        .await
        .set_trust(&agent_id, trust_level);

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// GET /task-lists
async fn list_task_lists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let entries: Vec<TaskListEntry> = lists
        .keys()
        .map(|id| TaskListEntry {
            id: id.clone(),
            topic: id.clone(), // topic is used as ID
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "task_lists": entries }))
}

/// POST /task-lists
async fn create_task_list(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTaskListRequest>,
) -> impl IntoResponse {
    match state.agent.create_task_list(&req.name, &req.topic).await {
        Ok(handle) => {
            let id = req.topic.clone();
            state.task_lists.write().await.insert(id.clone(), handle);
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "ok": true, "id": id })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// GET /task-lists/:id/tasks
async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "task list not found" })),
        );
    };

    match handle.list_tasks().await {
        Ok(tasks) => {
            let entries: Vec<TaskEntry> = tasks
                .into_iter()
                .map(|t| TaskEntry {
                    id: format!("{}", t.id),
                    title: t.title,
                    description: t.description,
                    state: format!("{:?}", t.state),
                    assignee: t.assignee.map(|a| format!("{a}")),
                    priority: t.priority,
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "tasks": entries })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// POST /task-lists/:id/tasks
async fn add_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddTaskRequest>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "task list not found" })),
        );
    };

    match handle.add_task(req.title, req.description).await {
        Ok(task_id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "ok": true, "task_id": format!("{task_id}") })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

/// PATCH /task-lists/:id/tasks/:tid
async fn update_task(
    State(state): State<Arc<AppState>>,
    Path((id, tid)): Path<(String, String)>,
    Json(req): Json<UpdateTaskRequest>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "task list not found" })),
        );
    };

    // Parse task ID from hex
    let task_id_bytes: [u8; 32] = match hex::decode(&tid) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "ok": false, "error": "invalid task ID (expected 64 hex chars)" }),
                ),
            );
        }
    };
    let task_id = x0x::crdt::TaskId::from_bytes(task_id_bytes);

    let result = match req.action.as_str() {
        "claim" => handle.claim_task(task_id).await,
        "complete" => handle.complete_task(task_id).await,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "ok": false, "error": "action must be 'claim' or 'complete'" }),
                ),
            );
        }
    };

    match result {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("{e}") })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load configuration from TOML file.
async fn load_config(path: &str) -> Result<DaemonConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config file: {path}"))?;
    toml::from_str(&content).with_context(|| format!("failed to parse config file: {path}"))
}

/// Initialize structured logging.
fn init_logging(level: &str) -> Result<()> {
    let level_filter = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level_filter)
        .init();

    Ok(())
}
