//! Route handlers (`category: "files"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::sse::SseEvent;
use super::super::state::AppState;
use super::super::{api_error, bad_request, not_found, parse_agent_id_hex};
use crate as x0x;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use x0x::contacts::TrustLevel;
use x0x::identity::AgentId;

fn file_transfer_now() -> (u64, u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs(), now.as_millis() as u64)
}

pub(in crate::server) fn file_transfer_send_config() -> x0x::dm::DmSendConfig {
    let mut config = x0x::dm::DmSendConfig {
        prefer_raw_quic_if_connected: true,
        stop_fallback_on_raw_error: false,
        ..x0x::dm::DmSendConfig::default()
    };
    // File transfer has a stronger application-level ChunkAck after the
    // receiver persists each chunk, but the raw receive-ACK still matters for
    // stale raw connections: without it, ant-quic can report local send
    // success while the receiver never drains the chunk, leaving the sender to
    // fail only after the 60s application ack timeout. Keep the raw fast path,
    // but allow capability-aware gossip fallback when that raw receive-ACK
    // fails. DEFAULT_CHUNK_SIZE is sized to fit the DM envelope cap.
    config.raw_quic_receive_ack_timeout = Some(Duration::from_secs(8));
    config
}

fn file_transfer_control_send_config() -> x0x::dm::DmSendConfig {
    let mut config = file_transfer_send_config();
    // Offer/accept/reject/complete are low-volume control messages. They must
    // not be fire-and-forget: a stale raw connection can otherwise report local
    // send success while the peer never updates transfer state.
    config.raw_quic_receive_ack_timeout = Some(Duration::from_secs(8));
    config.stop_fallback_on_raw_error = false;
    config
}

/// Maximum number of file chunks a sender may have in flight (sent but
/// not yet acked) at any time. Caps the broadcast/queue pressure that
/// caused the 100M chunk-loss regression on 2026-04-30 — the previous
/// fire-and-forget loop bursted 3200 chunks faster than the receiver's
/// disk write rate, overflowing tokio's `broadcast::channel(256)` and
/// silently shedding chunks. With a window of 8, the sender can never
/// have more than 8 chunks ahead of the receiver's last ack.
const FILE_CHUNK_WINDOW: u64 = 8;

/// Maximum time the sender will wait for a single chunk ack before
/// considering the transfer failed. Generous enough to cover one
/// cross-continent disk-write round-trip; the receiver disk write +
/// QUIC return path is the slow leg.
const FILE_CHUNK_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Per-transfer chunk-ack slot. The sender registers this when it begins
/// streaming chunks; the file-message listener bumps `last_acked` and wakes
/// any waiter every time a `FileMessage::ChunkAck` lands for this transfer;
/// the sender's chunk loop blocks on `wait_for_chunk_window` when its in-flight
/// budget would exceed `FILE_CHUNK_WINDOW`.
pub(crate) struct FileChunkAckSlot {
    /// Highest contiguous sequence number the receiver has acked.
    /// `u64::MAX` is the sentinel for "no ack received yet".
    last_acked: AtomicU64,
    /// Notified every time `last_acked` changes.
    notify: tokio::sync::Notify,
}

impl FileChunkAckSlot {
    pub(in crate::server) fn new() -> Self {
        Self {
            last_acked: AtomicU64::new(u64::MAX),
            notify: tokio::sync::Notify::new(),
        }
    }

    pub(in crate::server) fn record_ack(&self, sequence: u64) {
        // last_acked = max(last_acked, sequence), treating u64::MAX as -infinity.
        let mut current = self.last_acked.load(Ordering::SeqCst);
        loop {
            let new = if current == u64::MAX {
                sequence
            } else {
                current.max(sequence)
            };
            match self.last_acked.compare_exchange_weak(
                current,
                new,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        self.notify.notify_waiters();
    }

    /// Highest contiguous sequence acked, or `-1` if none acked yet (the
    /// `u64::MAX` sentinel). For `welcome.trace` diagnostics.
    pub(in crate::server) fn highest_acked(&self) -> i64 {
        let v = self.last_acked.load(Ordering::SeqCst);
        if v == u64::MAX {
            -1
        } else {
            v as i64
        }
    }
}

/// Block until `last_acked >= n.saturating_sub(FILE_CHUNK_WINDOW)`, i.e.
/// until the sender's in-flight count would drop back to (or below) the
/// window. For the first `FILE_CHUNK_WINDOW` chunks this returns immediately
/// because the window isn't yet saturated.
pub(in crate::server) async fn wait_for_chunk_window(
    slot: &FileChunkAckSlot,
    n: u64,
) -> std::result::Result<(), String> {
    if n < FILE_CHUNK_WINDOW {
        return Ok(());
    }
    let required = n - FILE_CHUNK_WINDOW;
    let deadline = tokio::time::Instant::now() + FILE_CHUNK_ACK_TIMEOUT;
    loop {
        let acked = slot.last_acked.load(Ordering::SeqCst);
        if acked != u64::MAX && acked >= required {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timeout waiting for file chunk ack >= {required}; last_acked={}",
                if acked == u64::MAX {
                    "<none>".to_string()
                } else {
                    acked.to_string()
                }
            ));
        }
        let notified = slot.notify.notified();
        tokio::pin!(notified);
        tokio::select! {
            _ = notified.as_mut() => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

async fn send_file_message(
    state: &Arc<AppState>,
    agent_id: &AgentId,
    msg: &x0x::files::FileMessage,
) -> std::result::Result<x0x::dm::DmReceipt, String> {
    let payload = serde_json::to_vec(msg).map_err(|e| format!("serialization failed: {e}"))?;
    state
        .agent
        .send_direct_with_config(agent_id, payload, file_transfer_control_send_config())
        .await
        .map_err(|e| e.to_string())
}

async fn send_file_chunk_message(
    state: &Arc<AppState>,
    agent_id: &AgentId,
    msg: &x0x::files::FileMessage,
) -> std::result::Result<x0x::dm::DmReceipt, String> {
    let payload = serde_json::to_vec(msg).map_err(|e| format!("serialization failed: {e}"))?;
    state
        .agent
        .send_direct_with_config(agent_id, payload, file_transfer_send_config())
        .await
        .map_err(|e| e.to_string())
}

/// POST /files/send — initiate a file transfer to an agent.
pub(in crate::server) async fn file_send_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id_hex = body.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
    let filename = body
        .get("filename")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed");
    let size = body.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
    let sha256 = body.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
    let mut source_path = body
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if agent_id_hex.is_empty() || sha256.is_empty() {
        return bad_request("agent_id and sha256 are required");
    }

    let agent_id = match parse_agent_id_hex(agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"ok": false, "error": e})),
            );
        }
    };

    let transfer_id = uuid::Uuid::new_v4().to_string();
    let (now_secs, now_ms) = file_transfer_now();

    if source_path.is_empty() {
        if let Some(data_b64) = body
            .get("data_b64")
            .or_else(|| body.get("data_base64"))
            .and_then(|v| v.as_str())
        {
            let data = match BASE64.decode(data_b64) {
                Ok(data) => data,
                Err(e) => {
                    return bad_request(format!("invalid data_b64: {e}"));
                }
            };
            if data.len() as u64 != size {
                return bad_request("data_b64 length does not match size");
            }
            let actual_sha = hex::encode(Sha256::digest(&data));
            if !sha256.eq_ignore_ascii_case(&actual_sha) {
                return bad_request("data_b64 sha256 mismatch");
            }
            if let Err(e) = tokio::fs::create_dir_all(&state.transfers_dir).await {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to create transfer spool: {e}"),
                );
            }
            let spool_path = state.transfers_dir.join(format!("{transfer_id}.send"));
            if let Err(e) = tokio::fs::write(&spool_path, data).await {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to spool upload: {e}"),
                );
            }
            source_path = spool_path.to_string_lossy().into_owned();
        }
    }

    let chunk_size = x0x::files::DEFAULT_CHUNK_SIZE;
    let total_chunks = x0x::files::total_chunks_for_size(size, chunk_size);

    let transfer = x0x::files::TransferState {
        transfer_id: transfer_id.clone(),
        direction: x0x::files::TransferDirection::Sending,
        remote_agent_id: agent_id_hex.to_string(),
        filename: filename.to_string(),
        total_size: size,
        bytes_transferred: 0,
        status: x0x::files::TransferStatus::Pending,
        sha256: sha256.to_string(),
        error: None,
        started_at: now_secs,
        started_at_unix_ms: now_ms,
        completed_at_unix_ms: None,
        source_path: if source_path.is_empty() {
            None
        } else {
            Some(source_path)
        },
        output_path: None,
        chunk_size,
        total_chunks,
    };

    state
        .file_transfers
        .write()
        .await
        .insert(transfer_id.clone(), transfer);

    // Send offer to remote agent via direct messaging
    let offer = x0x::files::FileMessage::Offer(x0x::files::FileOffer {
        transfer_id: transfer_id.clone(),
        filename: filename.to_string(),
        size,
        sha256: sha256.to_string(),
        chunk_size,
        total_chunks,
    });

    match send_file_message(&state, &agent_id, &offer).await {
        Ok(receipt) => {
            tracing::info!(path = ?receipt.path, retries = receipt.retries_used, "File offer sent: {transfer_id} -> {agent_id_hex}");
            (
                StatusCode::OK,
                Json(serde_json::json!({"ok": true, "transfer_id": transfer_id})),
            )
        }
        Err(e) => {
            tracing::error!("Failed to send file offer: {e}");
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(&transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(format!("Failed to send offer: {e}"));
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("send offer failed: {e}"),
            )
        }
    }
}

/// GET /files/transfers — list all file transfers.
pub(in crate::server) async fn file_transfers_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let transfers = state.file_transfers.read().await;
    let list: Vec<&x0x::files::TransferState> = transfers.values().collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "transfers": list})),
    )
}

/// GET /files/transfers/:id — get a single transfer's status.
pub(in crate::server) async fn file_transfer_status_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let transfers = state.file_transfers.read().await;
    match transfers.get(&id) {
        Some(t) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "transfer": t})),
        ),
        None => not_found("transfer not found"),
    }
}

/// POST /files/accept/:id — accept an incoming transfer.
pub(in crate::server) async fn file_accept_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let remote_agent_hex;
    {
        let mut transfers = state.file_transfers.write().await;
        match transfers.get_mut(&id) {
            Some(t)
                if t.status == x0x::files::TransferStatus::Pending
                    && t.direction == x0x::files::TransferDirection::Receiving =>
            {
                t.status = x0x::files::TransferStatus::InProgress;
                remote_agent_hex = t.remote_agent_id.clone();
            }
            Some(_) => {
                return bad_request("transfer is not a pending receive");
            }
            None => {
                return not_found("transfer not found");
            }
        }
    }

    // Send accept message back to the sender
    let agent_id = match parse_agent_id_hex(&remote_agent_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": e})),
            );
        }
    };

    let accept_msg = x0x::files::FileMessage::Accept {
        transfer_id: id.clone(),
    };
    let delivery_failed = match send_file_message(&state, &agent_id, &accept_msg).await {
        Ok(receipt) => {
            tracing::info!(path = ?receipt.path, retries = receipt.retries_used, "File accept sent: {id} -> {remote_agent_hex}");
            false
        }
        Err(e) => {
            tracing::warn!("Failed to send accept to sender: {e}");
            true
        }
    };

    if delivery_failed {
        // Revert to Pending so the accept can be retried
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&id) {
            t.status = x0x::files::TransferStatus::Pending;
        }
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "accepted but failed to notify sender — reverted to pending",
        )
    } else {
        (StatusCode::OK, Json(serde_json::json!({"ok": true})))
    }
}

/// POST /files/reject/:id — reject an incoming transfer.
pub(in crate::server) async fn file_reject_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let reason = body
        .as_ref()
        .and_then(|b| b.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("rejected by user")
        .to_string();

    let remote_agent_hex;
    {
        let mut transfers = state.file_transfers.write().await;
        match transfers.get_mut(&id) {
            Some(t) if t.status == x0x::files::TransferStatus::Pending => {
                t.status = x0x::files::TransferStatus::Rejected;
                t.error = Some(reason.clone());
                t.completed_at_unix_ms = Some(file_transfer_now().1);
                remote_agent_hex = t.remote_agent_id.clone();
            }
            Some(_) => {
                return bad_request("transfer is not pending");
            }
            None => {
                return not_found("transfer not found");
            }
        }
    }

    // Send reject message back to the sender
    let mut delivery_failed = false;
    if let Ok(agent_id) = parse_agent_id_hex(&remote_agent_hex) {
        let reject_msg = x0x::files::FileMessage::Reject {
            transfer_id: id.clone(),
            reason,
        };
        if let Err(e) = send_file_message(&state, &agent_id, &reject_msg).await {
            tracing::warn!("Failed to send reject to sender: {e}");
            delivery_failed = true;
        }
    }

    if delivery_failed {
        (
            StatusCode::OK,
            Json(
                serde_json::json!({"ok": true, "warning": "rejected locally but failed to notify sender"}),
            ),
        )
    } else {
        (StatusCode::OK, Json(serde_json::json!({"ok": true})))
    }
}

// ---------------------------------------------------------------------------
// Doctor — local/runtime diagnostics
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Self-update (gossip-based + GitHub fallback)
// ---------------------------------------------------------------------------

/// Dispatch an incoming `FileMessage` from the direct messaging channel.
pub(in crate::server) async fn handle_file_message(
    state: &Arc<AppState>,
    sender: &AgentId,
    msg: x0x::files::FileMessage,
) {
    match msg {
        x0x::files::FileMessage::Offer(offer) => {
            handle_file_offer(state, sender, offer).await;
        }
        x0x::files::FileMessage::Accept { transfer_id } => {
            handle_file_accept(state, sender, &transfer_id).await;
        }
        x0x::files::FileMessage::Reject {
            transfer_id,
            reason,
        } => {
            handle_file_reject(state, sender, &transfer_id, &reason).await;
        }
        x0x::files::FileMessage::Chunk(chunk) => {
            handle_file_chunk(state, sender, chunk).await;
        }
        x0x::files::FileMessage::Complete(complete) => {
            handle_file_complete(state, sender, complete).await;
        }
        x0x::files::FileMessage::ChunkAck {
            transfer_id,
            sequence,
        } => {
            // Wake the sender's chunk loop. Acks for unknown transfers
            // (already torn down, never started here) are silently dropped.
            if let Some(slot) = state.file_chunk_acks.read().await.get(&transfer_id) {
                slot.record_ack(sequence);
            }
        }
    }
}

/// Handle an incoming file offer — create a receiving TransferState.
async fn handle_file_offer(state: &Arc<AppState>, sender: &AgentId, offer: x0x::files::FileOffer) {
    let sender_hex = hex::encode(sender.as_bytes());

    // Trust filtering: reject offers from blocked agents
    {
        let contacts = state.contacts.read().await;
        if let Some(contact) = contacts.get(sender) {
            if contact.trust_level == TrustLevel::Blocked {
                tracing::info!("Rejected file offer from blocked agent: {sender_hex}");
                return;
            }
        }
    }

    if !is_safe_file_transfer_id(&offer.transfer_id) {
        tracing::warn!(
            "Rejected file offer from {sender_hex}: invalid transfer id {}",
            offer.transfer_id
        );
        return;
    }

    // Size limit check
    if offer.size > x0x::files::MAX_TRANSFER_SIZE {
        tracing::warn!(
            "Rejected file offer from {sender_hex}: size {} exceeds max {}",
            offer.size,
            x0x::files::MAX_TRANSFER_SIZE
        );
        return;
    }

    tracing::info!(
        "Incoming file offer: {} ({} bytes) from {}",
        offer.filename,
        offer.size,
        sender_hex
    );

    let (now_secs, now_ms) = file_transfer_now();

    let transfer = x0x::files::TransferState {
        transfer_id: offer.transfer_id.clone(),
        direction: x0x::files::TransferDirection::Receiving,
        remote_agent_id: sender_hex.clone(),
        filename: offer.filename.clone(),
        total_size: offer.size,
        bytes_transferred: 0,
        status: x0x::files::TransferStatus::Pending,
        sha256: offer.sha256,
        error: None,
        started_at: now_secs,
        started_at_unix_ms: now_ms,
        completed_at_unix_ms: None,
        source_path: None,
        output_path: None,
        chunk_size: offer.chunk_size,
        total_chunks: offer.total_chunks,
    };

    state
        .file_transfers
        .write()
        .await
        .insert(offer.transfer_id.clone(), transfer);

    // Emit SSE event so apps can be notified
    let _ = state.broadcast_tx.send(SseEvent {
        event_type: "file:offer".to_string(),
        data: serde_json::json!({
            "transfer_id": offer.transfer_id,
            "filename": offer.filename,
            "size": offer.size,
            "sender": sender_hex,
        }),
    });
}

fn is_safe_file_transfer_id(transfer_id: &str) -> bool {
    match uuid::Uuid::parse_str(transfer_id) {
        Ok(uuid) => transfer_id == uuid.hyphenated().to_string(),
        Err(_) => false,
    }
}

fn safe_file_transfer_part_path(
    transfers_dir: &FsPath,
    transfer_id: &str,
) -> std::result::Result<PathBuf, String> {
    if !is_safe_file_transfer_id(transfer_id) {
        return Err(format!("invalid file transfer id: {transfer_id}"));
    }
    Ok(transfers_dir.join(format!("{transfer_id}.part")))
}

/// Handle an incoming accept — start streaming chunks to the receiver.
async fn handle_file_accept(state: &Arc<AppState>, sender: &AgentId, transfer_id: &str) {
    let sender_hex = hex::encode(sender.as_bytes());
    tracing::info!("File accept received: {transfer_id} from {sender_hex}");

    let source_path;
    let sha256;
    let remote_agent_hex;
    {
        let mut transfers = state.file_transfers.write().await;
        let Some(t) = transfers.get_mut(transfer_id) else {
            tracing::warn!("Accept for unknown transfer: {transfer_id}");
            return;
        };
        if t.direction != x0x::files::TransferDirection::Sending
            || t.status != x0x::files::TransferStatus::Pending
        {
            tracing::warn!("Accept for non-pending sending transfer: {transfer_id}");
            return;
        }
        // Authenticate: sender must match the remote_agent_id we sent the offer to
        if t.remote_agent_id != sender_hex {
            tracing::warn!(
                "Accept from wrong agent for {transfer_id}: expected {} got {sender_hex}",
                t.remote_agent_id
            );
            return;
        }
        t.status = x0x::files::TransferStatus::InProgress;
        source_path = t.source_path.clone();
        sha256 = t.sha256.clone();
        remote_agent_hex = t.remote_agent_id.clone();
    }

    let Some(path) = source_path else {
        tracing::error!("No source path for transfer {transfer_id}");
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some("No source path available".to_string());
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
        return;
    };

    let Ok(agent_id) = parse_agent_id_hex(&remote_agent_hex) else {
        tracing::error!("Invalid agent_id in transfer {transfer_id}");
        return;
    };

    // Spawn async task to stream chunks
    let state = Arc::clone(state);
    let transfer_id = transfer_id.to_string();
    tokio::spawn(async move {
        stream_file_chunks(&state, &transfer_id, &path, &sha256, &agent_id).await;
    });
}

/// Stream file chunks to the receiver via direct messaging.
///
/// Sends chunks over the existing direct-QUIC path (`prefer_raw_quic_if_connected`)
/// with a windowed application-level ACK protocol on top: the sender registers
/// a `FileChunkAckSlot`, waits for `FileMessage::ChunkAck` from the receiver
/// to advance the in-flight window, and only allows up to `FILE_CHUNK_WINDOW`
/// chunks ahead of the last ack at any time. This caps queue pressure on the
/// receiver's `subscribe_direct` subscriber queue and prevents the silent
/// chunk-loss regression that bricked 100M transfers on 2026-04-30.
async fn stream_file_chunks(
    state: &Arc<AppState>,
    transfer_id: &str,
    source_path: &str,
    sha256: &str,
    agent_id: &AgentId,
) {
    use tokio::io::AsyncReadExt;

    // Register an ack slot before we start streaming so any acks that race
    // ahead of our first chunk are not dropped.
    let ack_slot = Arc::new(FileChunkAckSlot::new());
    state
        .file_chunk_acks
        .write()
        .await
        .insert(transfer_id.to_string(), Arc::clone(&ack_slot));

    // Helper that always cleans up the ack slot, regardless of how the
    // streaming task exits.
    let mark_failed = |state: &Arc<AppState>, transfer_id: &str, error: String| {
        let state = Arc::clone(state);
        let transfer_id = transfer_id.to_string();
        async move {
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(&transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(error);
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
        }
    };

    let mut file = match tokio::fs::File::open(source_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Cannot open file {source_path}: {e}");
            mark_failed(state, transfer_id, format!("Cannot open file: {e}")).await;
            state.file_chunk_acks.write().await.remove(transfer_id);
            return;
        }
    };

    let mut buf = vec![0u8; x0x::files::DEFAULT_CHUNK_SIZE];
    let mut sequence: u64 = 0;

    loop {
        let n = match file.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                tracing::error!("Read error on {source_path}: {e}");
                mark_failed(state, transfer_id, format!("Read error: {e}")).await;
                state.file_chunk_acks.write().await.remove(transfer_id);
                return;
            }
        };

        // Apply windowed back-pressure before sending: never have more than
        // FILE_CHUNK_WINDOW chunks ahead of the receiver's last ack.
        if let Err(e) = wait_for_chunk_window(&ack_slot, sequence).await {
            tracing::error!("Chunk window wait failed for {transfer_id}: {e}");
            mark_failed(state, transfer_id, e).await;
            state.file_chunk_acks.write().await.remove(transfer_id);
            return;
        }

        let chunk_data = BASE64.encode(&buf[..n]);
        let chunk_msg = x0x::files::FileMessage::Chunk(x0x::files::FileChunk {
            transfer_id: transfer_id.to_string(),
            sequence,
            data: chunk_data,
        });

        if let Err(e) = send_file_chunk_message(state, agent_id, &chunk_msg).await {
            tracing::error!("Send chunk {sequence} failed: {e}");
            mark_failed(
                state,
                transfer_id,
                format!("Send failed at chunk {sequence}: {e}"),
            )
            .await;
            state.file_chunk_acks.write().await.remove(transfer_id);
            return;
        }

        // Update progress
        {
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(transfer_id) {
                t.bytes_transferred += n as u64;
            }
        }

        sequence += 1;
    }

    // Drain the in-flight window: wait until the receiver has acked every
    // chunk we sent before declaring the transfer Complete. Without this,
    // the Complete message can arrive before the receiver has processed the
    // last few chunks, which is exactly what the receiver logged as
    // "file complete arrived before final chunk; deferring finalize".
    if sequence > 0 {
        let last_seq = sequence - 1;
        if let Err(e) = wait_for_final_acks(&ack_slot, last_seq).await {
            tracing::error!("Final chunk ack wait failed for {transfer_id}: {e}");
            mark_failed(state, transfer_id, e).await;
            state.file_chunk_acks.write().await.remove(transfer_id);
            return;
        }
    }

    // Send completion message
    let complete_msg = x0x::files::FileMessage::Complete(x0x::files::FileComplete {
        transfer_id: transfer_id.to_string(),
        sha256: sha256.to_string(),
    });

    if let Err(e) = send_file_message(state, agent_id, &complete_msg).await {
        tracing::error!("Send complete message failed: {e}");
        mark_failed(state, transfer_id, format!("Send complete failed: {e}")).await;
        state.file_chunk_acks.write().await.remove(transfer_id);
        return;
    }

    // Mark as complete on sender side
    {
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Complete;
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
    }
    state.file_chunk_acks.write().await.remove(transfer_id);
    tracing::info!("File transfer complete (sender): {transfer_id}");
}

/// Block until the receiver has acked every chunk up to and including
/// `last_seq`. Used after the sender's final chunk so we don't send the
/// Complete envelope before the receiver has seen the chunks.
pub(in crate::server) async fn wait_for_final_acks(
    slot: &FileChunkAckSlot,
    last_seq: u64,
) -> std::result::Result<(), String> {
    let deadline = tokio::time::Instant::now() + FILE_CHUNK_ACK_TIMEOUT;
    loop {
        let acked = slot.last_acked.load(Ordering::SeqCst);
        if acked != u64::MAX && acked >= last_seq {
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timeout waiting for final chunk ack >= {last_seq}; last_acked={}",
                if acked == u64::MAX {
                    "<none>".to_string()
                } else {
                    acked.to_string()
                }
            ));
        }
        let notified = slot.notify.notified();
        tokio::pin!(notified);
        tokio::select! {
            _ = notified.as_mut() => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

/// Handle an incoming reject — mark the sending transfer as rejected.
async fn handle_file_reject(
    state: &Arc<AppState>,
    sender: &AgentId,
    transfer_id: &str,
    reason: &str,
) {
    let sender_hex = hex::encode(sender.as_bytes());
    tracing::info!("File reject received: {transfer_id} from {sender_hex} — {reason}");
    let mut transfers = state.file_transfers.write().await;
    if let Some(t) = transfers.get_mut(transfer_id) {
        if t.direction == x0x::files::TransferDirection::Sending {
            // Authenticate: sender must match the remote_agent_id
            if t.remote_agent_id != sender_hex {
                tracing::warn!(
                    "Reject from wrong agent for {transfer_id}: expected {} got {sender_hex}",
                    t.remote_agent_id
                );
                return;
            }
            t.status = x0x::files::TransferStatus::Rejected;
            t.error = Some(reason.to_string());
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
    }
}

/// Handle an incoming file chunk — append to partial file.
/// Clean up partial file and hasher state for a failed transfer.
async fn cleanup_failed_transfer(state: &Arc<AppState>, transfer_id: &str) {
    // Remove .part file
    match safe_file_transfer_part_path(&state.transfers_dir, transfer_id) {
        Ok(part_path) => {
            let _ = tokio::fs::remove_file(&part_path).await;
        }
        Err(e) => {
            tracing::warn!("Skipping partial file cleanup: {e}");
        }
    }

    // Remove hasher + any buffered out-of-order chunks
    state.receive_hashers.write().await.remove(transfer_id);
    state.pending_file_chunks.write().await.remove(transfer_id);
}

async fn handle_file_chunk(state: &Arc<AppState>, sender: &AgentId, chunk: x0x::files::FileChunk) {
    let sender_hex = hex::encode(sender.as_bytes());

    // Validate: transfer must exist, be a receiving transfer, be InProgress,
    // and the sender must match the original offer's remote_agent_id.
    let expected_sequence = {
        let transfers = state.file_transfers.read().await;
        match transfers.get(&chunk.transfer_id) {
            Some(t) => match x0x::files::receive_chunk_expected_sequence(t, &sender_hex) {
                Ok(sequence) => sequence,
                Err(x0x::files::FileChunkValidationError::WrongSender) => {
                    tracing::warn!(
                        "Chunk from wrong agent for {}: expected {} got {sender_hex}",
                        chunk.transfer_id,
                        t.remote_agent_id
                    );
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        "Ignoring chunk for transfer {} (dir={:?} status={:?})",
                        chunk.transfer_id,
                        t.direction,
                        t.status
                    );
                    return;
                }
            },
            None => {
                tracing::warn!("Ignoring chunk for unknown transfer {}", chunk.transfer_id);
                return;
            }
        }
    };

    let data = match BASE64.decode(&chunk.data) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Chunk decode error for {}: {e}", chunk.transfer_id);
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(format!("Chunk decode error: {e}"));
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
            drop(transfers);
            cleanup_failed_transfer(state, &chunk.transfer_id).await;
            return;
        }
    };

    if chunk.sequence < expected_sequence {
        tracing::debug!(
            transfer_id = %chunk.transfer_id,
            sequence = chunk.sequence,
            expected_sequence,
            "ignoring duplicate/stale file chunk"
        );
        return;
    }

    if chunk.sequence > expected_sequence {
        let mut pending = state.pending_file_chunks.write().await;
        let entry = pending.entry(chunk.transfer_id.clone()).or_default();
        if entry.insert(chunk.sequence, data).is_some() {
            tracing::debug!(
                transfer_id = %chunk.transfer_id,
                sequence = chunk.sequence,
                "replaced buffered out-of-order file chunk"
            );
        } else {
            tracing::debug!(
                transfer_id = %chunk.transfer_id,
                sequence = chunk.sequence,
                expected_sequence,
                "buffered out-of-order file chunk"
            );
        }
        // Ack even for buffered chunks: it lets the sender's window advance.
        send_chunk_ack(state, sender, &chunk.transfer_id, chunk.sequence).await;
        return;
    }

    let chunk_seq = chunk.sequence;
    if let Err(e) = apply_ready_file_chunks(state, &chunk.transfer_id, chunk.sequence, data).await {
        tracing::error!("File chunk apply failed for {}: {e}", chunk.transfer_id);
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(&chunk.transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(e);
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
        drop(transfers);
        cleanup_failed_transfer(state, &chunk.transfer_id).await;
        return;
    }

    // Successful apply — ack the chunk so the sender's in-flight window
    // can advance. Ack carries this chunk's sequence; if `apply_ready_file_chunks`
    // drained additional buffered chunks above this one, those were already
    // acked when they arrived (out-of-order buffer path above).
    send_chunk_ack(state, sender, &chunk.transfer_id, chunk_seq).await;
}

/// Send a `FileMessage::ChunkAck` back to the sender. Failures to send the
/// ack are logged but not propagated — the sender's ack-wait timeout will
/// surface a stuck transfer if too many acks go missing.
async fn send_chunk_ack(state: &Arc<AppState>, sender: &AgentId, transfer_id: &str, sequence: u64) {
    let ack = x0x::files::FileMessage::ChunkAck {
        transfer_id: transfer_id.to_string(),
        sequence,
    };
    if let Err(e) = send_file_message(state, sender, &ack).await {
        tracing::warn!(transfer_id, sequence, "failed to send file chunk ack: {e}");
    }
}

async fn apply_ready_file_chunks(
    state: &Arc<AppState>,
    transfer_id: &str,
    first_sequence: u64,
    first_data: Vec<u8>,
) -> std::result::Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let part_path = safe_file_transfer_part_path(&state.transfers_dir, transfer_id)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part_path)
        .await
        .map_err(|e| format!("Cannot write chunk: {e}"))?;

    let mut sequence = first_sequence;
    let mut data = first_data;

    loop {
        let (expected_sequence, new_total, total_size) = {
            let transfers = state.file_transfers.read().await;
            let t = transfers
                .get(transfer_id)
                .ok_or_else(|| "transfer disappeared during chunk apply".to_string())?;
            let expected = if t.chunk_size > 0 {
                t.bytes_transferred / t.chunk_size as u64
            } else {
                0
            };
            if sequence != expected {
                return Err(format!(
                    "Out-of-order chunk: expected {} got {}",
                    expected, sequence
                ));
            }
            let new_total = t.bytes_transferred + data.len() as u64;
            if new_total > t.total_size {
                return Err(format!(
                    "Received data exceeds declared file size: {} + {} > {}",
                    t.bytes_transferred,
                    data.len(),
                    t.total_size
                ));
            }
            (expected, new_total, t.total_size)
        };

        file.write_all(&data)
            .await
            .map_err(|e| format!("Write failed: {e}"))?;

        {
            let mut hashers = state.receive_hashers.write().await;
            hashers
                .entry(transfer_id.to_string())
                .or_insert_with(Sha256::new)
                .update(&data);
        }

        let maybe_expected_sha256 = {
            let mut transfers = state.file_transfers.write().await;
            let t = transfers
                .get_mut(transfer_id)
                .ok_or_else(|| "transfer disappeared while updating progress".to_string())?;
            t.bytes_transferred = new_total;
            if t.bytes_transferred == t.total_size {
                Some(t.sha256.clone())
            } else {
                None
            }
        };

        if let Some(expected_sha256) = maybe_expected_sha256 {
            finalize_received_transfer(state, transfer_id, &expected_sha256).await;
            return Ok(());
        }

        let next_sequence = expected_sequence + 1;
        let maybe_buffered = {
            let mut pending = state.pending_file_chunks.write().await;
            let next = pending
                .get_mut(transfer_id)
                .and_then(|buffer| buffer.remove(&next_sequence));
            let empty = pending
                .get(transfer_id)
                .is_some_and(std::collections::BTreeMap::is_empty);
            if empty {
                pending.remove(transfer_id);
            }
            next
        };

        match maybe_buffered {
            Some(next) => {
                sequence = next_sequence;
                data = next;
            }
            None => {
                if new_total < total_size {
                    return Ok(());
                }
                return Ok(());
            }
        }
    }
}

async fn finalize_received_transfer(
    state: &Arc<AppState>,
    transfer_id: &str,
    expected_sha256: &str,
) {
    let part_path = match safe_file_transfer_part_path(&state.transfers_dir, transfer_id) {
        Ok(path) => path,
        Err(e) => {
            tracing::error!("Cannot finalize received transfer: {e}");
            let mut transfers = state.file_transfers.write().await;
            if let Some(t) = transfers.get_mut(transfer_id) {
                t.status = x0x::files::TransferStatus::Failed;
                t.error = Some(e);
                t.completed_at_unix_ms = Some(file_transfer_now().1);
            }
            return;
        }
    };

    let computed_hash = {
        let mut hashers = state.receive_hashers.write().await;
        match hashers.remove(transfer_id) {
            Some(hasher) => hex::encode(hasher.finalize()),
            None => {
                tracing::error!("No hasher found for transfer {transfer_id}");
                let mut transfers = state.file_transfers.write().await;
                if let Some(t) = transfers.get_mut(transfer_id) {
                    t.status = x0x::files::TransferStatus::Failed;
                    t.error = Some("No hash state found".to_string());
                    t.completed_at_unix_ms = Some(file_transfer_now().1);
                }
                return;
            }
        }
    };

    if computed_hash != expected_sha256 {
        tracing::error!(
            "SHA-256 mismatch for {transfer_id}: expected {} got {}",
            expected_sha256,
            computed_hash
        );
        let _ = tokio::fs::remove_file(&part_path).await;
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!(
                "SHA-256 mismatch: expected {} got {}",
                expected_sha256, computed_hash
            ));
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
        return;
    }

    let raw_filename = {
        let transfers = state.file_transfers.read().await;
        transfers
            .get(transfer_id)
            .map(|t| t.filename.clone())
            .unwrap_or_else(|| transfer_id.to_string())
    };
    let filename = x0x::files::received_file_output_name(transfer_id, &raw_filename);

    let final_path = state.transfers_dir.join(&filename);
    if let Err(e) = tokio::fs::rename(&part_path, &final_path).await {
        tracing::error!("Failed to rename part file: {e}");
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Failed;
            t.error = Some(format!("Failed to finalize file: {e}"));
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
        return;
    }

    {
        let mut transfers = state.file_transfers.write().await;
        if let Some(t) = transfers.get_mut(transfer_id) {
            t.status = x0x::files::TransferStatus::Complete;
            t.output_path = Some(final_path.to_string_lossy().to_string());
            t.completed_at_unix_ms = Some(file_transfer_now().1);
        }
    }
    state.pending_file_chunks.write().await.remove(transfer_id);

    let _ = state.broadcast_tx.send(SseEvent {
        event_type: "file:complete".to_string(),
        data: serde_json::json!({
            "transfer_id": transfer_id,
            "filename": filename,
            "sha256": computed_hash,
            "path": final_path.to_string_lossy(),
        }),
    });

    tracing::info!(
        "File transfer complete (receiver): {} -> {}",
        transfer_id,
        final_path.display()
    );
}

/// Handle a file-complete message — verify SHA-256 and finalize.
async fn handle_file_complete(
    state: &Arc<AppState>,
    sender: &AgentId,
    complete: x0x::files::FileComplete,
) {
    tracing::info!("File complete received: {}", complete.transfer_id);

    let sender_hex = hex::encode(sender.as_bytes());

    // Validate: transfer must exist, be receiving, be InProgress,
    // and the sender must match the original offer's remote_agent_id.
    // If the sender's complete arrives before the last chunk is processed,
    // defer finalization — the chunk handler will finalize as soon as the
    // declared byte count has been received.
    let (expected_sha256, bytes_transferred, total_size) = {
        let transfers = state.file_transfers.read().await;
        match transfers.get(&complete.transfer_id) {
            Some(t)
                if t.direction == x0x::files::TransferDirection::Receiving
                    && t.status == x0x::files::TransferStatus::InProgress =>
            {
                if t.remote_agent_id != sender_hex {
                    tracing::warn!(
                        "Complete from wrong agent for {}: expected {} got {sender_hex}",
                        complete.transfer_id,
                        t.remote_agent_id
                    );
                    return;
                }
                (t.sha256.clone(), t.bytes_transferred, t.total_size)
            }
            Some(t) => {
                tracing::warn!(
                    "Ignoring complete for transfer {} (dir={:?} status={:?})",
                    complete.transfer_id,
                    t.direction,
                    t.status
                );
                return;
            }
            None => {
                tracing::warn!(
                    "Ignoring complete for unknown transfer {}",
                    complete.transfer_id
                );
                return;
            }
        }
    };

    if bytes_transferred < total_size {
        tracing::info!(
            transfer_id = %complete.transfer_id,
            bytes_transferred,
            total_size,
            "file complete arrived before final chunk; deferring finalize until declared bytes are received"
        );
        return;
    }

    finalize_received_transfer(state, &complete.transfer_id, &expected_sha256).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_file_transfer_id_accepts_canonical_uuid() {
        let transfer_id = uuid::Uuid::new_v4().to_string();
        assert!(is_safe_file_transfer_id(&transfer_id));

        let transfers_dir = PathBuf::from("/tmp/x0x-transfers");
        let part_path = safe_file_transfer_part_path(&transfers_dir, &transfer_id);
        assert_eq!(
            part_path,
            Ok(transfers_dir.join(format!("{transfer_id}.part")))
        );
    }

    #[test]
    fn safe_file_transfer_id_rejects_path_traversal_and_noncanonical_ids() {
        let uuid = uuid::Uuid::new_v4().to_string();
        let invalid_ids = vec![
            "../../escape".to_string(),
            "../escape".to_string(),
            "subdir/file".to_string(),
            r"subdir\file".to_string(),
            "..".to_string(),
            String::new(),
            uuid.to_uppercase(),
            format!("urn:uuid:{uuid}"),
            format!("{{{uuid}}}"),
        ];

        for transfer_id in invalid_ids {
            assert!(!is_safe_file_transfer_id(&transfer_id));
            assert!(
                safe_file_transfer_part_path(FsPath::new("/tmp/x0x-transfers"), &transfer_id)
                    .is_err()
            );
        }
    }

    #[test]
    fn file_chunk_ack_slot_records_max() {
        let slot = FileChunkAckSlot::new();
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), u64::MAX);
        slot.record_ack(5);
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), 5);
        // Older sequence does not regress the high-watermark.
        slot.record_ack(3);
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), 5);
        // Higher sequence advances it.
        slot.record_ack(9);
        assert_eq!(slot.last_acked.load(Ordering::SeqCst), 9);
    }

    #[tokio::test]
    async fn wait_for_chunk_window_does_not_block_inside_window() {
        let slot = FileChunkAckSlot::new();
        // For chunks 0..FILE_CHUNK_WINDOW the window isn't saturated yet.
        for n in 0..FILE_CHUNK_WINDOW {
            wait_for_chunk_window(&slot, n)
                .await
                .expect("must return Ok inside the window");
        }
    }

    #[tokio::test]
    async fn wait_for_chunk_window_releases_when_ack_arrives() {
        let slot = Arc::new(FileChunkAckSlot::new());
        // Sending chunk N=FILE_CHUNK_WINDOW requires ack of chunk 0.
        let n = FILE_CHUNK_WINDOW;
        let waiter_slot = Arc::clone(&slot);
        let waiter = tokio::spawn(async move { wait_for_chunk_window(&waiter_slot, n).await });

        // Give the waiter a chance to park, then deliver the ack.
        tokio::time::sleep(Duration::from_millis(50)).await;
        slot.record_ack(0);

        let res = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must release before the test timeout")
            .expect("waiter task did not panic");
        res.expect("must succeed once ack >= n - WINDOW arrives");
    }

    #[tokio::test]
    async fn wait_for_final_acks_returns_when_last_seq_acked() {
        let slot = Arc::new(FileChunkAckSlot::new());
        let waiter_slot = Arc::clone(&slot);
        let waiter = tokio::spawn(async move { wait_for_final_acks(&waiter_slot, 100).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        slot.record_ack(99); // not enough
        tokio::time::sleep(Duration::from_millis(50)).await;
        slot.record_ack(100); // exact match — must release

        let res = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must release before the test timeout")
            .expect("waiter task did not panic");
        res.expect("must succeed once ack >= last_seq arrives");
    }

    #[test]
    fn file_transfer_control_messages_are_acked_but_chunks_are_windowed() {
        let control = file_transfer_control_send_config();
        assert!(control.prefer_raw_quic_if_connected);
        assert!(!control.stop_fallback_on_raw_error);
        assert_eq!(
            control.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );

        let chunk = file_transfer_send_config();
        assert!(chunk.prefer_raw_quic_if_connected);
        assert!(!chunk.stop_fallback_on_raw_error);
        assert_eq!(
            chunk.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
    }
}
