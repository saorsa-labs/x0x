//! Task-list REST handlers (`category: "tasks"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate as x0x;

use super::super::state::AppState;
use super::super::{api_error, bad_request, not_found};

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

/// POST /task-lists request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateTaskListRequest {
    pub(in crate::server) name: String,
    pub(in crate::server) topic: String,
}

/// POST /task-lists/:id/tasks request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct AddTaskRequest {
    pub(in crate::server) title: String,
    #[serde(default)]
    pub(in crate::server) description: Option<String>,
}

/// PATCH /task-lists/:id/tasks/:tid request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct UpdateTaskRequest {
    pub(in crate::server) action: String, // "claim" or "complete"
}

/// Task list entry.
#[derive(Debug, Serialize)]
pub(in crate::server) struct TaskListEntry {
    pub(in crate::server) id: String,
    pub(in crate::server) topic: String,
}

/// Task snapshot for API response.
#[derive(Debug, Serialize)]
pub(in crate::server) struct TaskEntry {
    pub(in crate::server) id: String,
    pub(in crate::server) title: String,
    pub(in crate::server) description: String,
    pub(in crate::server) state: String,
    pub(in crate::server) assignee: Option<String>,
    pub(in crate::server) priority: u8,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /task-lists
pub(in crate::server) async fn list_task_lists(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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
pub(in crate::server) async fn create_task_list(
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
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /task-lists/:id/tasks
pub(in crate::server) async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    match handle.list_tasks().await {
        Ok(tasks) => {
            let entries: Vec<TaskEntry> = tasks
                .into_iter()
                .map(|t| TaskEntry {
                    id: format!("{}", t.id),
                    title: t.title,
                    description: t.description,
                    state: format!("{}", t.state),
                    assignee: t.assignee.map(|a| format!("{a}")),
                    priority: t.priority,
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "tasks": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// POST /task-lists/:id/tasks
pub(in crate::server) async fn add_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddTaskRequest>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    match handle
        .add_task(req.title, req.description.unwrap_or_default())
        .await
    {
        Ok(task_id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "ok": true, "task_id": format!("{task_id}") })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// PATCH /task-lists/:id/tasks/:tid
pub(in crate::server) async fn update_task(
    State(state): State<Arc<AppState>>,
    Path((id, tid)): Path<(String, String)>,
    Json(req): Json<UpdateTaskRequest>,
) -> impl IntoResponse {
    let lists = state.task_lists.read().await;
    let Some(handle) = lists.get(&id) else {
        return not_found("task list not found");
    };

    // Parse task ID from hex
    let task_id_bytes: [u8; 32] = match hex::decode(&tid) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid task ID (expected 64 hex chars)");
        }
    };
    let task_id = x0x::crdt::TaskId::from_bytes(task_id_bytes);

    let result = match req.action.as_str() {
        "claim" => handle.claim_task(task_id).await,
        "complete" => handle.complete_task(task_id).await,
        _ => {
            return bad_request("action must be 'claim' or 'complete'");
        }
    };

    match result {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}
