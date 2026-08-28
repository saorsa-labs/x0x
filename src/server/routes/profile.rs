//! Owner/self-profile route handlers (ADR-0036): `GET/PUT /profile` and
//! `GET /owner/agents`.
//!
//! The profile is daemon-persisted state (`<data_dir>/profile.json`), not
//! client state — names must survive GUI resets and be consistent across
//! every client of this daemon. `display_name` feeds the V3 announce
//! self-name; `human_name` feeds the agent card's `owner_name`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde::Serialize;

use super::super::state::AppState;
use super::status::ApiResponse;

/// GET /profile response body.
#[derive(Debug, Serialize)]
pub(in crate::server) struct ProfileData {
    /// Owner's human name.
    pub(in crate::server) human_name: Option<String>,
    /// This agent's display name (announced as the V3 self-name).
    pub(in crate::server) display_name: Option<String>,
    /// Label for this machine.
    pub(in crate::server) machine_name: Option<String>,
}

/// PUT /profile request body — every field optional; only present fields
/// are applied (partial update semantics, see [`SelfProfile::merge`]).
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct UpdateProfileRequest {
    #[serde(default)]
    pub(in crate::server) human_name: Option<String>,
    #[serde(default)]
    pub(in crate::server) display_name: Option<String>,
    #[serde(default)]
    pub(in crate::server) machine_name: Option<String>,
}

/// GET /profile — the daemon's stored self-profile.
pub(in crate::server) async fn get_profile(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<ProfileData>> {
    let profile = state.profile.read().await;
    Json(ApiResponse {
        ok: true,
        data: ProfileData {
            human_name: profile.human_name.clone(),
            display_name: profile.display_name.clone(),
            machine_name: profile.machine_name.clone(),
        },
    })
}

/// PUT /profile — partially update and persist the self-profile.
///
/// Setting `display_name` live-updates the identity announce self-name (the
/// next V3 beat carries it); clearing it (JSON `null`) reverts to anonymous
/// beats. The persisted file is the source of truth across restarts.
pub(in crate::server) async fn update_profile(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateProfileRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Review P2: validate BEFORE persisting or announcing anything. An
    // empty string is the explicit CLEAR sentinel and skips validation;
    // a non-empty value must be a sane bounded name (no control chars,
    // <= 128 bytes) — names reach profile.json, the announce wire, and
    // signed agent cards.
    for (field, value) in [
        ("human_name", &req.human_name),
        ("display_name", &req.display_name),
        ("machine_name", &req.machine_name),
    ] {
        if let Some(v) = value {
            if !v.is_empty() {
                if let Err(reason) = crate::profile::SelfProfile::validate_name(field, v) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "ok": false, "error": reason })),
                    );
                }
            }
        }
    }
    let update = crate::profile::SelfProfile {
        // Trim accepted names so whitespace never reaches the wire; keep
        // the empty-string clear sentinel intact.
        human_name: req.human_name.as_ref().map(|v| v.trim().to_string()),
        display_name: req.display_name.as_ref().map(|v| v.trim().to_string()),
        machine_name: req.machine_name.as_ref().map(|v| v.trim().to_string()),
    };
    let (profile, persist_err) = {
        let mut profile = state.profile.write().await;
        let _changed = profile.merge(&update);
        let persist_err = profile.save_to(&state.profile_path).await.err();
        // The announce name follows the stored profile even if persistence
        // fails — the daemon's live view stays coherent; the error is
        // reported so the operator can fix the disk.
        state.agent.set_self_name(profile.display_name.clone());
        (profile.clone(), persist_err)
    };
    if let Some(e) = persist_err {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "ok": false,
                "error": format!("failed to persist profile: {e}"),
            })),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "profile": {
                "human_name": profile.human_name,
                "display_name": profile.display_name,
                "machine_name": profile.machine_name,
            },
        })),
    )
}

/// One entry of the `GET /owner/agents` roster.
#[derive(Debug, Serialize)]
pub(in crate::server) struct OwnerAgentEntry {
    /// Hex agent id from the certificate.
    pub(in crate::server) agent_id: String,
    /// Certificate expiry (unix seconds), `None` = no expiry.
    pub(in crate::server) cert_not_after: Option<u64>,
    /// Contact-store label, when the agent is a contact.
    pub(in crate::server) label: Option<String>,
    /// V3 announce self-name, when seen on the mesh.
    pub(in crate::server) self_name: Option<String>,
    /// Machine id (hex) the agent last announced from, if discovered.
    pub(in crate::server) machine_id: Option<String>,
    /// True for this daemon's own agent.
    pub(in crate::server) is_local: bool,
}

/// GET /owner/agents — the roster of agents certified by this install's
/// owner (ADR-0036): certificates this daemon has VERIFIED for the owner's
/// `UserId` (its own, the owner's signed announcement roster, and certs
/// embedded in discovered beats), joined with the contact store and the
/// discovery cache for names. Honest scope (review P1): best-effort and
/// discovery-derived — not a persisted issuance journal; owned agents that
/// are offline and uncached drop out after restart until re-observed.
/// `409` when no user identity (and therefore no owner) is configured.
pub(in crate::server) async fn owner_agents(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(owner) = state.agent.user_id() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "no owner: this daemon has no user identity (run `x0x user-id create`)",
            })),
        );
    };
    let certs = state.agent.owner_issued_certificates().await;
    let contacts = state.contacts.read().await;
    let local_agent_id = state.agent.agent_id();
    let mut entries = Vec::with_capacity(certs.len());
    for cert in &certs {
        let Ok(agent_id) = cert.agent_id() else {
            continue;
        };
        // Enrichment is best-effort: the roster is certificate-authoritative,
        // names/machines come from whatever this daemon has seen.
        let discovered = state.agent.discovered_agent(agent_id).await.ok().flatten();
        entries.push(OwnerAgentEntry {
            agent_id: hex::encode(agent_id.as_bytes()),
            cert_not_after: cert.not_after(),
            label: contacts.get(&agent_id).and_then(|c| c.label.clone()),
            self_name: discovered.as_ref().and_then(|d| d.self_name.clone()),
            machine_id: discovered
                .as_ref()
                .map(|d| hex::encode(d.machine_id.as_bytes())),
            is_local: agent_id == local_agent_id,
        });
    }
    entries.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "owner_user_id": hex::encode(owner.as_bytes()),
            "agents": entries,
        })),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::server::routes::named_groups::tests::secure_endpoint_test_state_at;
    use axum::http::StatusCode as SC;
    use std::sync::Arc;

    /// Build an agent + AppState over a fresh temp data dir. The shared
    /// helper (named_groups tests) loads the self-profile from the data
    /// dir, exactly like `serve` does — which is what the restart test
    /// below relies on.
    async fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await
                .unwrap(),
        );
        let state = secure_endpoint_test_state_at(&data_dir, agent)
            .await
            .unwrap();
        (state, dir)
    }

    /// WHY (ADR-0036 validation): profile names are daemon state — a PUT
    /// must survive a daemon restart (simulated by re-loading state from
    /// the same data dir), or names would be client-local again.
    #[tokio::test]
    async fn profile_put_round_trips_across_restart() {
        let (state, dir) = test_state().await;
        let body = UpdateProfileRequest {
            human_name: Some("David Irvine".to_string()),
            display_name: Some("fae".to_string()),
            machine_name: Some("m5-max".to_string()),
        };
        let (code, resp) = update_profile(State(Arc::clone(&state)), Json(body)).await;
        assert_eq!(code, SC::OK, "{}", resp.0);

        // Restart: a fresh AppState + Agent from the same data dir must see
        // the persisted names — persistence must not depend on the process.
        let data_dir = dir.path().to_path_buf();
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine2.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await
                .unwrap(),
        );
        let state2 = secure_endpoint_test_state_at(&data_dir, agent)
            .await
            .unwrap();
        let Json(ApiResponse { ok, data }) = get_profile(State(state2)).await;
        assert!(ok);
        assert_eq!(data.human_name.as_deref(), Some("David Irvine"));
        assert_eq!(data.display_name.as_deref(), Some("fae"));
        assert_eq!(data.machine_name.as_deref(), Some("m5-max"));
    }

    /// WHY: `display_name` is what the announce path reads — a PUT must
    /// live-update the agent's self-name without a daemon restart, and a
    /// partial PUT must not clobber the other fields.
    #[tokio::test]
    async fn profile_put_updates_agent_self_name_and_is_partial() {
        let (state, _dir) = test_state().await;
        let (code, _) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: Some("David".to_string()),
                display_name: None,
                machine_name: None,
            }),
        )
        .await;
        assert_eq!(code, SC::OK);
        assert_eq!(state.agent.self_name(), None, "no display_name yet");

        let (code, _) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: None,
                display_name: Some("fae".to_string()),
                machine_name: None,
            }),
        )
        .await;
        assert_eq!(code, SC::OK);
        assert_eq!(state.agent.self_name(), Some("fae".to_string()));

        let Json(ApiResponse { data, .. }) = get_profile(State(state)).await;
        assert_eq!(
            data.human_name.as_deref(),
            Some("David"),
            "partial PUT must not clear untouched fields"
        );
    }

    /// WHY (ADR-0036): GET /agent must surface the stored names — the
    /// response is what clients render, and names must come from daemon
    /// state, not browser localStorage.
    #[tokio::test]
    async fn agent_info_surfaces_profile_names() {
        use super::super::identity::agent_info;
        use axum::Json;

        let (state, _dir) = test_state().await;
        let (code, _) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: Some("David Irvine".to_string()),
                display_name: Some("fae".to_string()),
                machine_name: Some("m5-max".to_string()),
            }),
        )
        .await;
        assert_eq!(code, SC::OK);

        let Json(resp) = agent_info(State(state)).await;
        let data = serde_json::to_value(&resp.data).unwrap();
        assert_eq!(data["human_name"], "David Irvine");
        assert_eq!(data["display_name"], "fae");
        assert_eq!(data["machine_name"], "m5-max");
    }

    /// WHY (ADR-0036): `?display_name=` is deprecated — the stored profile
    /// must win over the query parameter so a card can no longer disagree
    /// with what the daemon announces, and the owner name must ride the
    /// card from the profile's human_name.
    #[tokio::test]
    async fn agent_card_prefers_stored_profile_over_deprecated_query_param() {
        use super::super::identity::{get_agent_card, CardQuery};

        let (state, _dir) = test_state().await;
        let (code, _) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: Some("David Irvine".to_string()),
                display_name: Some("fae".to_string()),
                machine_name: None,
            }),
        )
        .await;
        assert_eq!(code, SC::OK);

        use axum::response::IntoResponse as _;
        let response = get_agent_card(
            State(Arc::clone(&state)),
            axum::extract::Query(CardQuery {
                display_name: Some("query-param-name".to_string()),
                include_groups: None,
                include_local_addresses: false,
            }),
        )
        .await
        .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["card"]["display_name"], "fae",
            "stored profile display_name must beat the deprecated query param"
        );
        assert_eq!(
            json["card"]["owner_name"], "David Irvine",
            "owner_name must come from the stored profile human_name"
        );
    }

    /// WHY (review P2): names persist and propagate to the wire and cards —
    /// garbage must be rejected with 400 BEFORE persistence, and an empty
    /// string must CLEAR the stored name (null/omitted keeps it).
    #[tokio::test]
    async fn profile_put_validates_names_and_empty_string_clears() {
        let (state, _dir) = test_state().await;

        // Oversized and control-character names are rejected, nothing persisted.
        let (code, body) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: Some(format!("x{}", "y".repeat(200))),
                display_name: None,
                machine_name: None,
            }),
        )
        .await;
        assert_eq!(code, SC::BAD_REQUEST, "{}", body.0);
        let (code, body) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: Some("bad\u{0007}name".to_string()),
                display_name: None,
                machine_name: None,
            }),
        )
        .await;
        assert_eq!(code, SC::BAD_REQUEST, "{}", body.0);
        let Json(ApiResponse { data, .. }) = get_profile(State(Arc::clone(&state))).await;
        assert!(
            data.human_name.is_none(),
            "rejected writes must not persist"
        );

        // Set, then clear with the empty string; null keeps the rest.
        let (code, _) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: Some("David".to_string()),
                display_name: Some("fae".to_string()),
                machine_name: None,
            }),
        )
        .await;
        assert_eq!(code, SC::OK);
        let (code, _) = update_profile(
            State(Arc::clone(&state)),
            Json(UpdateProfileRequest {
                human_name: Some(String::new()), // explicit clear
                display_name: None,              // keep
                machine_name: None,
            }),
        )
        .await;
        assert_eq!(code, SC::OK);
        let Json(ApiResponse { data, .. }) = get_profile(State(state)).await;
        assert_eq!(data.human_name, None, "empty string clears");
        assert_eq!(data.display_name.as_deref(), Some("fae"), "null keeps");
        assert_eq!(
            crate::profile::SelfProfile::default(),
            crate::profile::SelfProfile::default()
        );
    }

    /// WHY: `/owner/agents` is the "my agents" list ADR 0007 implied — it
    /// must be derived from issued certificates, and a daemon whose owner
    /// issued exactly one cert (its own agent) reports exactly that agent.
    /// With no user identity there is no owner and the endpoint must say so
    /// instead of returning an empty roster that reads as "no agents".
    #[tokio::test]
    async fn owner_agents_matches_issued_certificates() {
        let (state, dir) = test_state().await;
        let (code, body) = owner_agents(State(Arc::clone(&state))).await;
        assert_eq!(code, SC::CONFLICT, "{}", body.0);

        let data_dir = dir.path().to_path_buf();
        let user = crate::identity::UserKeypair::generate().unwrap();
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("owner-machine.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
                .with_user_key(user)
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await
                .unwrap(),
        );
        let state2 = secure_endpoint_test_state_at(&data_dir, agent)
            .await
            .unwrap();
        let (code, body) = owner_agents(State(Arc::clone(&state2))).await;
        assert_eq!(code, SC::OK, "{}", body.0);
        let agents = body["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 1, "own issued cert only: {}", body.0);
        assert_eq!(
            agents[0]["agent_id"],
            hex::encode(state2.agent.agent_id().as_bytes())
        );
        assert_eq!(agents[0]["is_local"], serde_json::json!(true));
    }
}
