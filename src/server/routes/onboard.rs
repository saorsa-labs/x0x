//! `GET /onboard` (`category: "identity"`) — the install-and-join recipe
//! that teaches a non-x0x agent to install x0x and DM this daemon's agent
//! (#894, R11).
//!
//! The recipe builder lives in [`crate::onboard`], shared with the
//! `x0x onboard` CLI command, so the REST and CLI surfaces cannot drift.
//! The handler's own work is small: read the daemon's signed card (the same
//! base card `GET /agent/card` serves, without group invites), pick the
//! card-delivery variant the query asks for, and answer with the recipe in
//! both Markdown and structured form plus the signed card link.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate as x0x;

use super::super::state::AppState;
use super::identity::{build_base_card, finish_signed_card};

/// Default file name the recipe tells the new agent to `cat` when the card
/// travels beside the recipe instead of inside it.
const DEFAULT_CARD_FILE: &str = "x0x-invite-card.txt";

/// Query params for GET /onboard.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct OnboardQuery {
    /// Card delivery: `"file"` (default — the recipe imports a handed-over
    /// file and the response carries the link separately), `"inline"` (the
    /// ~20 KB link is embedded in the recipe's import command) or
    /// `"lookup"` (no card; the new agent finds the inviter by id).
    #[serde(default)]
    card: Option<String>,
    /// File name the recipe's import step reads in `file` delivery
    /// (default `x0x-invite-card.txt`). A bare name, not a path.
    #[serde(default)]
    card_file: Option<String>,
}

/// GET /onboard — emit the install-and-join recipe for this agent.
pub(in crate::server) async fn get_onboard(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<OnboardQuery>,
) -> impl IntoResponse {
    let delivery = query.card.as_deref().unwrap_or("file");
    if !matches!(delivery, "file" | "inline" | "lookup") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "card must be one of: file, inline, lookup"
            })),
        )
            .into_response();
    }
    let card_file = query
        .card_file
        .unwrap_or_else(|| DEFAULT_CARD_FILE.to_string());
    if let Err(e) = x0x::onboard::validate_card_file_name(&card_file) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }

    let agent_id = hex::encode(state.agent.agent_id().as_bytes());
    // The id and link are pasted into shell commands by the recipe; the
    // daemon validates its own values exactly like the CLI used to, so a
    // malformed value can never reach another agent's shell.
    if let Err(e) = x0x::onboard::validate_agent_id(&agent_id) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }
    let link = if delivery == "lookup" {
        None
    } else {
        let mut card = build_base_card(&state, None, false).await;
        let link = finish_signed_card(&state, &mut card).await;
        if let Err(e) = x0x::onboard::validate_card_link(&link) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
        Some(link)
    };

    let card_ref = match (delivery, link.as_deref()) {
        ("inline", Some(link)) => x0x::onboard::Card::Inline(link),
        ("file", Some(_)) => x0x::onboard::Card::File(&card_file),
        _ => x0x::onboard::Card::Lookup,
    };
    let recipe = x0x::onboard::recipe_text(&agent_id, &card_ref);
    let steps = x0x::onboard::recipe_json(
        &agent_id,
        &card_ref,
        (delivery == "file").then_some(card_file.as_str()),
    );

    Json(serde_json::json!({
        "ok": true,
        "inviter_agent_id": agent_id,
        "card_delivery": delivery,
        // The signed link (~20 KB). In `file` delivery the caller hands it
        // over beside the recipe (the CLI writes it to --card-file); in
        // `inline` it is already inside the recipe; `lookup` has none.
        "card_link": link,
        "recipe": recipe,
        "steps": steps["steps"],
        "install_script": x0x::onboard::INSTALL_SH_URL,
        "windows_install": format!("irm {} | iex", x0x::onboard::INSTALL_PS1_URL),
        "reference": x0x::onboard::SKILL_URL,
    }))
    .into_response()
}
