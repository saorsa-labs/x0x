//! Route handlers (`category: "trust"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use crate as x0x;
use super::super::{bad_request, parse_agent_id_hex};
use super::super::state::AppState;
use std::sync::Arc;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use x0x::identity::MachineId;

/// POST /trust/evaluate request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct EvaluateTrustRequest {
    /// Agent ID as hex string.
    agent_id: String,
    /// Machine ID as hex string.
    machine_id: String,
}

/// POST /trust/evaluate — evaluate trust decision for an (agent, machine) pair.
pub(in crate::server) async fn evaluate_trust(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvaluateTrustRequest>,
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

    let machine_bytes = match hex::decode(&req.machine_id) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid machine_id hex");
        }
    };
    let machine_id = MachineId(machine_bytes);

    let store = state.contacts.read().await;
    let evaluator = x0x::trust::TrustEvaluator::new(&store);
    let ctx = x0x::trust::TrustContext {
        agent_id: &agent_id,
        machine_id: &machine_id,
    };
    let decision = evaluator.evaluate(&ctx);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "decision": format!("{:?}", decision)
        })),
    )
}
