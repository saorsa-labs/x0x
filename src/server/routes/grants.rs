//! Route handlers for ADR-0070 §2 share grants (`category: "grants"` in
//! `src/api/mod.rs`): issue, list and revoke grants this install's owner
//! signed, and list grants this install received.
//!
//! Every route is owner/durable-token only. `auth_middleware` refuses
//! session bearers and riders before any extractor runs
//! (`requires_durable_owner`); the handlers re-check as defense in depth.

use super::super::api_error;
use super::super::rider_auth::ActorContext;
use super::super::state::AppState;
use crate as x0x;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use x0x::identity::{AgentId, UserId};
use x0x::share_grant::{
    GrantRole, Grantee, ShareCap, ShareGrant, ShareGrantError, MAX_SHARE_GRANT_LIFETIME_SECS,
};

const DURABLE_REQUIRED: &str =
    "share-grant management requires the durable API token (not a session or rider token)";

fn forbidden() -> Response {
    api_error(StatusCode::FORBIDDEN, DURABLE_REQUIRED).into_response()
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_id32(field: &str, raw: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(raw).map_err(|e| format!("{field}: invalid hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{field}: expected 32 bytes (64 hex chars)"))
}

fn bad_request(msg: String) -> Response {
    api_error(StatusCode::BAD_REQUEST, msg).into_response()
}

/// Parse a list of 64-hex agent ids; the error names `field` and the
/// first bad id.
fn parse_agent_ids(field: &str, raw: &[String]) -> Result<Vec<AgentId>, String> {
    raw.iter()
        .map(|id| parse_id32(field, id).map(AgentId))
        .collect()
}

/// The `409` answer when this install has no owner key to sign grants
/// with; `None` when it has one.
fn missing_owner_key(state: &AppState) -> Option<Response> {
    state.agent.identity().user_keypair().is_none().then(|| {
        api_error(
            StatusCode::CONFLICT,
            "share grants need an owner identity (user key) on this install",
        )
        .into_response()
    })
}

fn grant_error(err: &ShareGrantError) -> Response {
    let status = match err {
        ShareGrantError::Invalid(_)
        | ShareGrantError::BadSignature(_)
        | ShareGrantError::Malformed(_)
        | ShareGrantError::Expired => StatusCode::BAD_REQUEST,
        ShareGrantError::NotForUs | ShareGrantError::Conflict => StatusCode::CONFLICT,
        ShareGrantError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    api_error(status, err.to_string()).into_response()
}

/// `POST /grants` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct GrantIssueRequest {
    /// Grantee user id (hex). Exactly one of `grantee_user` /
    /// `grantee_agent`.
    #[serde(default)]
    grantee_user: Option<String>,
    /// Grantee agent id (hex), for a grantee with no user identity.
    #[serde(default)]
    grantee_agent: Option<String>,
    /// This owner's agents to share (hex, non-empty).
    agents: Vec<String>,
    /// Capabilities: `"dm"`, `"exec"`, `"group_invite"`, `"call"`,
    /// `{"connect":{"ports":[22]}}`,
    /// `{"data":{"group":"<stable id>","store":"scratch","access":"ro"|"rw"}}`.
    caps: Vec<ShareCap>,
    /// Unix seconds the grant starts (default: now).
    #[serde(default)]
    not_before: Option<u64>,
    /// Unix seconds the grant ends. Exactly one of `expiry` / `ttl_secs`.
    #[serde(default)]
    expiry: Option<u64>,
    /// Lifetime from `not_before`, in seconds.
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Extra agents (hex) to deliver the grant to, beyond the grantee's
    /// known agents and the shared agents' daemons.
    #[serde(default)]
    deliver_to: Vec<String>,
    /// ADR 0079: carry the owner's name and the shared machines' names to
    /// capable grantees in the v2 envelope (default). `false` (the CLI's
    /// `--no-names`) withholds both and sends every recipient the plain v1
    /// grant.
    #[serde(default = "default_include_names")]
    include_names: bool,
}

fn default_include_names() -> bool {
    true
}

/// GET /grants — grants this install's owner issued, with status.
pub(in crate::server) async fn grants_list(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    list_role(&state, GrantRole::Issued).await
}

/// GET /grants/received — grants naming this install as grantee.
pub(in crate::server) async fn grants_received(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    list_role(&state, GrantRole::Received).await
}

async fn list_role(state: &AppState, role: GrantRole) -> Response {
    let Some(store) = state.agent.share_grant_store() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "share-grant store not installed",
        )
        .into_response();
    };
    let now = unix_now_secs();
    let mut views = Vec::new();
    for grant in store.grants(role) {
        let revoked = state.agent.is_share_grant_revoked(&grant).await;
        views.push(grant.to_view(now, revoked));
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "grants": views,
            "store_error": store.load_error(),
            "outbox_error": state
                .agent
                .share_grant_outbox()
                .and_then(|outbox| outbox.load_error().map(str::to_string)),
        })),
    )
        .into_response()
}

/// POST /grants — sign a grant with the owner key, store it, and deliver it
/// by durable DM to the grantee's known agents and to each shared agent's
/// daemon. `delivery` reports each recipient (delivered = its durable ACK
/// arrived). A failed delivery does not undo the grant; a shared agent's
/// daemon that did not receive it simply grants nothing (fail closed).
pub(in crate::server) async fn grants_issue(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<GrantIssueRequest>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    if let Some(resp) = missing_owner_key(&state) {
        return resp;
    }
    let grantee = match (&req.grantee_user, &req.grantee_agent) {
        (Some(user), None) => match parse_id32("grantee_user", user) {
            Ok(id) => Grantee::User(UserId(id)),
            Err(msg) => return bad_request(msg),
        },
        (None, Some(agent)) => match parse_id32("grantee_agent", agent) {
            Ok(id) => Grantee::Agent(AgentId(id)),
            Err(msg) => return bad_request(msg),
        },
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "set exactly one of grantee_user / grantee_agent",
            )
            .into_response()
        }
    };
    let agents = match parse_agent_ids("agents", &req.agents) {
        Ok(ids) => ids,
        Err(msg) => return bad_request(msg),
    };
    let deliver_to = match parse_agent_ids("deliver_to", &req.deliver_to) {
        Ok(ids) => ids,
        Err(msg) => return bad_request(msg),
    };
    let not_before = req.not_before.unwrap_or_else(unix_now_secs);
    let expiry = match (req.expiry, req.ttl_secs) {
        (Some(expiry), None) => expiry,
        (None, Some(ttl)) => not_before.saturating_add(ttl),
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "set exactly one of expiry / ttl_secs (grants must expire)",
            )
            .into_response()
        }
    };
    let grant = match state
        .agent
        .issue_share_grant(grantee, agents, req.caps, not_before, expiry)
        .await
    {
        Ok(grant) => grant,
        Err(err) => return grant_error(&err),
    };
    deliver_new_grant(&state, grant, &deliver_to, req.include_names, None).await
}

/// Deliver a newly signed and stored grant (issue or renewal) and build the
/// response. `renews` names the grant a renewal replaces.
async fn deliver_new_grant(
    state: &AppState,
    grant: ShareGrant,
    deliver_to: &[AgentId],
    include_names: bool,
    renews: Option<[u8; 32]>,
) -> Response {
    let recipients = state
        .agent
        .share_grant_recipients_classified(&grant, deliver_to)
        .await;
    // ADR 0079: build and sign the names section once; recipients whose
    // verified advert sets bit 14 (and only grantee-side ones) get the v2
    // envelope, everyone else the unchanged v1 payload.
    let envelope = if include_names {
        let (owner_name, own_machine_name) = {
            let profile = state.profile.read().await;
            (profile.human_name.clone(), profile.machine_name.clone())
        };
        let devices = state.owner_sync.as_ref().map(|s| &**s.store());
        match state
            .agent
            .grant_names_for(devices, owner_name, own_machine_name, &grant)
            .await
        {
            None => None,
            Some(names) => match state.agent.sign_grant_names(grant.clone(), names) {
                Ok(envelope) => Some(envelope),
                Err(err) => {
                    // Names are a default, not the grant: deliver v1 and say so.
                    tracing::warn!("grant names not signed; delivering v1 only: {err}");
                    None
                }
            },
        }
    } else {
        None
    };
    let delivery = state
        .agent
        .deliver_share_grant_with_names(&grant, &recipients, envelope.as_ref())
        .await;
    let mut body = serde_json::json!({
        "ok": true,
        "grant": grant.to_view(unix_now_secs(), false),
        "delivery": delivery,
    });
    if let Some(old) = renews {
        body["renews"] = serde_json::json!(hex::encode(old));
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// `POST /grants/:id/renew` body. Every field is optional; an empty body
/// takes every default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct GrantRenewRequest {
    /// Lifetime of the renewal from now, in seconds (default and maximum:
    /// 90 days, [`MAX_SHARE_GRANT_LIFETIME_SECS`]).
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Extra agents (hex) to deliver the renewal to, as for `POST /grants`.
    #[serde(default)]
    deliver_to: Vec<String>,
    /// As for `POST /grants` (default `true`).
    #[serde(default = "default_include_names")]
    include_names: bool,
}

/// POST /grants/:id/renew — renew an issued grant (#1350): sign a new grant
/// with the same grantee, agents and capabilities, valid from now for
/// `ttl_secs` (default 90 days), store it and deliver it as `POST /grants`
/// does. The old grant is not changed and stays valid to its own expiry, so
/// a renewal delivered before then leaves no gap. `404` when this install
/// did not issue the grant; `400` when it is revoked or `ttl_secs` is out
/// of range.
pub(in crate::server) async fn grants_renew(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    // An empty body takes every default; a body that is not a valid
    // request is refused, never read as the defaults.
    let raw: &[u8] = if body.iter().all(u8::is_ascii_whitespace) {
        b"{}"
    } else {
        &body
    };
    let req = match serde_json::from_slice::<GrantRenewRequest>(raw) {
        Ok(req) => req,
        Err(e) => return bad_request(format!("invalid renew body: {e}")),
    };
    let grant_id = match parse_id32("id", &id) {
        Ok(id) => id,
        Err(msg) => return bad_request(msg),
    };
    if let Some(resp) = missing_owner_key(&state) {
        return resp;
    }
    let deliver_to = match parse_agent_ids("deliver_to", &req.deliver_to) {
        Ok(ids) => ids,
        Err(msg) => return bad_request(msg),
    };
    let ttl = req.ttl_secs.unwrap_or(MAX_SHARE_GRANT_LIFETIME_SECS);
    let grant = match state
        .agent
        .renew_share_grant(&grant_id, ttl, unix_now_secs())
        .await
    {
        Ok(grant) => grant,
        Err(ShareGrantError::NotForUs) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "no grant with this id was issued by this install",
            )
            .into_response()
        }
        Err(err) => return grant_error(&err),
    };
    deliver_new_grant(
        &state,
        grant,
        &deliver_to,
        req.include_names,
        Some(grant_id),
    )
    .await
}

/// DELETE /grants/:id — revoke a grant with the owner key. Effective locally
/// at once; gossiped on `x0x.revocation.v3`. Answers success only once the
/// revocation and the removal of the grant's queued redeliveries (#926) are
/// durable; otherwise `503` (retry is idempotent, and only a successful
/// DELETE schedules pushes). `push` reports the best-effort direct
/// revocation pushes scheduled to capable recipients (#1003); the DELETE
/// does not wait for them, and gossip remains the backstop.
pub(in crate::server) async fn grants_revoke(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let grant_id = match parse_id32("id", &id) {
        Ok(id) => id,
        Err(msg) => return bad_request(msg),
    };
    if state.agent.identity().user_keypair().is_none() {
        return api_error(
            StatusCode::CONFLICT,
            "revoking a grant needs the owner key on this install",
        )
        .into_response();
    }
    let known = state
        .agent
        .share_grant_store()
        .is_some_and(|store| store.issued(&grant_id).is_some());
    match x0x::share_grant::revoke_share_grant_pushing(&state.agent, grant_id, None).await {
        Ok((_record, push)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "grant_id": hex::encode(grant_id),
                "revoked": true,
                "known": known,
                "push": push,
            })),
        )
            .into_response(),
        Err(err) => grant_error(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::{delete, get};
    use tower::ServiceExt;

    const DURABLE: &str = "test-token";

    fn grants_router(state: Arc<AppState>, with_auth: bool) -> axum::Router {
        let router = axum::Router::new()
            .route("/grants", get(grants_list).post(grants_issue))
            .route("/grants/received", get(grants_received))
            .route("/grants/:id", delete(grants_revoke))
            .route("/grants/:id/renew", axum::routing::post(grants_renew));
        let router = if with_auth {
            router.layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
        } else {
            router
        };
        router.with_state(state)
    }

    async fn send(
        app: &axum::Router,
        req: Request<axum::body::Body>,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let resp = app.clone().oneshot(req).await?;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
    }

    fn owner_req(
        method: &str,
        path: &str,
        body: &str,
    ) -> anyhow::Result<Request<axum::body::Body>> {
        Ok(Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .extension(ActorContext::Owner { durable: true })
            .body(axum::body::Body::from(body.to_string()))?)
    }

    fn issue_body() -> String {
        serde_json::json!({
            "grantee_user": "bb".repeat(32),
            "agents": ["aa".repeat(32)],
            "caps": ["dm", {"connect": {"ports": [22]}}],
            "ttl_secs": 3600,
        })
        .to_string()
    }

    /// WHY: every `/grants` route is wired and answers the ADR-0070 §2
    /// contract on an ownerless install: lists work (empty), issuing and
    /// revoking are refused (only an owner key can sign or revoke a grant),
    /// a malformed body or id is a client error, and a grant must expire.
    #[tokio::test]
    async fn grant_routes_wired() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        state.agent.install_share_grant_store(Arc::new(
            x0x::share_grant::ShareGrantStore::in_memory(state.agent.agent_id(), None),
        ));
        let app = grants_router(Arc::clone(&state), false);

        for path in ["/grants", "/grants/received"] {
            let (status, body) = send(&app, owner_req("GET", path, "")?).await?;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            assert_eq!(body["grants"], serde_json::json!([]), "{path}: {body}");
        }
        let (status, body) = send(&app, owner_req("POST", "/grants", &issue_body())?).await?;
        assert_eq!(status, StatusCode::CONFLICT, "ownerless issue: {body}");
        let (status, _) = send(
            &app,
            owner_req("POST", "/grants", r#"{"agents":[],"caps":[],"bogus":1}"#)?,
        )
        .await?;
        assert!(status.is_client_error(), "unknown field must be rejected");
        let (status, body) = send(
            &app,
            owner_req("DELETE", &format!("/grants/{}", "cc".repeat(32)), "")?,
        )
        .await?;
        assert_eq!(status, StatusCode::CONFLICT, "ownerless revoke: {body}");
        let (status, _) = send(&app, owner_req("DELETE", "/grants/not-hex", "")?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        Ok(())
    }

    /// WHY: grants decide who reaches the owner's agents; a session or rider
    /// token must never read, issue or revoke them.
    #[tokio::test]
    async fn grant_routes_refuse_session_and_rider_tokens() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let app = grants_router(Arc::clone(&state), true);
        let session = state.sessions.issue(std::time::Instant::now());
        let rider = {
            let mut store = state.rider_tokens.lock().await;
            let (token, _record) = store
                .issue(
                    "aa".repeat(32),
                    Vec::new(),
                    None,
                    60,
                    String::new(),
                    None,
                    None,
                    crate::server::rider_auth::unix_now_secs(),
                    Vec::new(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("rider token issue: {e}"))?;
            token
        };
        let surfaces = [
            ("GET", "/grants".to_string(), String::new()),
            ("GET", "/grants/received".to_string(), String::new()),
            ("POST", "/grants".to_string(), issue_body()),
            (
                "DELETE",
                format!("/grants/{}", "cc".repeat(32)),
                String::new(),
            ),
            (
                "POST",
                format!("/grants/{}/renew", "cc".repeat(32)),
                String::new(),
            ),
        ];
        for (method, path, body) in &surfaces {
            for (who, bearer) in [("session", session.as_str()), ("rider", rider.as_str())] {
                let req = Request::builder()
                    .method(*method)
                    .uri(path.as_str())
                    .header("authorization", format!("Bearer {bearer}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.clone()))?;
                let (status, json) = send(&app, req).await?;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{who} {method} {path}: {json}"
                );
            }
            let req = Request::builder()
                .method(*method)
                .uri(path.as_str())
                .header("authorization", format!("Bearer {DURABLE}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.clone()))?;
            let (status, json) = send(&app, req).await?;
            assert_ne!(
                status,
                StatusCode::FORBIDDEN,
                "durable {method} {path} must clear the gate: {json}"
            );
        }
        Ok(())
    }

    /// Advertise `bits` for `agent` as a verified capability advert, as the
    /// gossip advert service would ingest it.
    fn advertise(state: &AppState, agent: &x0x::identity::AgentId, bits: u64) {
        let mut caps = x0x::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
        caps.application_registry = x0x::dm::CapabilityRegistry { version: 1, bits };
        assert!(
            state.agent.capability_store.insert(
                *agent,
                x0x::identity::MachineId([0x5e; 32]),
                caps,
                x0x::dm_capability::now_unix_ms(),
            ),
            "the verified advert inserts"
        );
    }

    /// WHY (ADR 0079 §1, #1831 review): on an install WITH an owner, the
    /// default `POST /grants` (no `include_names`) signs the names and the
    /// delivery report says `v2` for a grantee whose verified advert sets
    /// bit 14, through the daemon's real capability gate. `include_names:
    /// false` sends v1. A grantee with no verified advert, and a
    /// `deliver_to` agent that is not the grantee, get v1.
    #[tokio::test]
    async fn grant_issue_sends_v2_only_to_a_bit_14_grantee_unless_names_are_withheld(
    ) -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_user_key(crate::identity::UserKeypair::from_seed(&[0x31; 32])?)
                .with_contact_store_path(dir.path().join("contacts.json"))
                .build()
                .await?,
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            dir.path(),
            agent,
        )
        .await?;
        state.agent.install_share_grant_store(Arc::new(
            x0x::share_grant::ShareGrantStore::in_memory(
                state.agent.agent_id(),
                state.agent.user_id(),
            ),
        ));
        state.profile.write().await.human_name = Some("Bob Smith".to_string());
        let capable = x0x::identity::AgentId([0xc1; 32]);
        let old = x0x::identity::AgentId([0xc2; 32]);
        advertise(
            &state,
            &capable,
            x0x::dm::CapabilityRegistry::current().bits,
        );
        let app = grants_router(Arc::clone(&state), false);
        let own = hex::encode(state.agent.agent_id().as_bytes());
        let issue = |grantee: &x0x::identity::AgentId, extra: serde_json::Value| {
            let mut body = serde_json::json!({
                "grantee_agent": hex::encode(grantee.as_bytes()),
                "agents": [own.clone()],
                "caps": ["dm"],
                "ttl_secs": 3600,
            });
            if let (Some(obj), Some(more)) = (body.as_object_mut(), extra.as_object()) {
                for (k, v) in more {
                    obj.insert(k.clone(), v.clone());
                }
            }
            body.to_string()
        };
        let envelope_for = |body: &serde_json::Value, agent: &x0x::identity::AgentId| {
            body["delivery"]
                .as_array()
                .and_then(|rows| {
                    rows.iter()
                        .find(|r| r["agent"] == hex::encode(agent.as_bytes()))
                })
                .map(|r| r["envelope"].clone())
        };

        let (status, body) = send(
            &app,
            owner_req("POST", "/grants", &issue(&capable, serde_json::json!({})))?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            envelope_for(&body, &capable),
            Some(serde_json::json!("v2")),
            "default include_names: {body}"
        );

        let (status, body) = send(
            &app,
            owner_req(
                "POST",
                "/grants",
                &issue(&capable, serde_json::json!({"include_names": false})),
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            envelope_for(&body, &capable),
            Some(serde_json::json!("v1")),
            "include_names=false: {body}"
        );

        let (status, body) = send(
            &app,
            owner_req(
                "POST",
                "/grants",
                &issue(
                    &old,
                    serde_json::json!({"deliver_to": [hex::encode(capable.as_bytes())]}),
                ),
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            envelope_for(&body, &old),
            Some(serde_json::json!("v1")),
            "no verified advert: {body}"
        );
        assert_eq!(
            envelope_for(&body, &capable),
            Some(serde_json::json!("v1")),
            "a deliver_to agent that is not the grantee: {body}"
        );
        Ok(())
    }

    /// WHY: #1003 — a successful DELETE reports its best-effort push
    /// scheduling: a held grant's recipients are counted and scheduled
    /// (an unknown-capability recipient counts as scheduled: it waits
    /// behind one targeted advert refresh), and a revocation for a grant
    /// this install does not hold schedules NO push (`push` all zeros) —
    /// its recipients are unknown here, and gossip is the only carrier.
    #[tokio::test]
    async fn grant_revoke_reports_push_scheduling() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let user = x0x::identity::UserKeypair::from_seed(&[0x51; 32])
            .map_err(|e| anyhow::anyhow!("user key: {e}"))?;
        let user_id = user.user_id();
        let grant_id = [0x52u8; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let grant = x0x::share_grant::ShareGrant::sign(
            &user,
            grant_id,
            x0x::share_grant::Grantee::Agent(x0x::identity::AgentId([0xBB; 32])),
            vec![x0x::identity::AgentId([0xBC; 32])],
            vec![x0x::share_grant::ShareCap::Dm],
            now - 60,
            now + 3600,
        )
        .map_err(|e| anyhow::anyhow!("sign grant: {e}"))?;
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_identity_dir(dir.path().join("identity"))
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key(
                    x0x::identity::AgentKeypair::generate()
                        .map_err(|e| anyhow::anyhow!("agent key: {e}"))?,
                )
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .build()
                .await
                .map_err(|e| anyhow::anyhow!("agent: {e}"))?,
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&agent),
        )
        .await?;
        let store = Arc::new(x0x::share_grant::ShareGrantStore::in_memory(
            agent.agent_id(),
            Some(user_id),
        ));
        store
            .accept(grant, now)
            .await
            .map_err(|e| anyhow::anyhow!("accept grant: {e}"))?;
        agent.install_share_grant_store(store);
        let app = grants_router(Arc::clone(&state), false);

        // A held grant: two recipients (the grantee agent and the shared
        // agent), capability unknown for both, so each is scheduled behind
        // the refresh-and-wait gate.
        let (status, body) = send(
            &app,
            owner_req("DELETE", &format!("/grants/{}", hex::encode(grant_id)), "")?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["revoked"], serde_json::json!(true), "{body}");
        assert_eq!(body["known"], serde_json::json!(true), "{body}");
        assert_eq!(body["push"]["recipients"], serde_json::json!(2), "{body}");
        assert_eq!(body["push"]["scheduled"], serde_json::json!(2), "{body}");
        assert_eq!(
            body["push"]["skipped_not_capable"],
            serde_json::json!(0),
            "{body}"
        );
        assert_eq!(
            body["push"]["skipped_bound"],
            serde_json::json!(0),
            "{body}"
        );

        // A grant this install does not hold: revoked (by id, gossip-only,
        // `grant_expiry` unknown) and NO push is scheduled.
        let (status, body) = send(
            &app,
            owner_req("DELETE", &format!("/grants/{}", "dd".repeat(32)), "")?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["known"], serde_json::json!(false), "{body}");
        for field in [
            "recipients",
            "scheduled",
            "skipped_not_capable",
            "skipped_bound",
        ] {
            assert_eq!(body["push"][field], serde_json::json!(0), "{field}: {body}");
        }
        Ok(())
    }

    /// An install with an owner key and an in-memory grant store.
    async fn owner_state() -> anyhow::Result<(Arc<AppState>, tempfile::TempDir)> {
        let dir = tempfile::tempdir()?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_user_key(crate::identity::UserKeypair::from_seed(&[0x35; 32])?)
                .with_contact_store_path(dir.path().join("contacts.json"))
                .build()
                .await?,
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            dir.path(),
            agent,
        )
        .await?;
        state.agent.install_share_grant_store(Arc::new(
            x0x::share_grant::ShareGrantStore::in_memory(
                state.agent.agent_id(),
                state.agent.user_id(),
            ),
        ));
        Ok((state, dir))
    }

    /// WHY (#1350, D35): a grant may last at most 90 days. `POST /grants`
    /// refuses a longer window (by `ttl_secs` or by `expiry`) and stores
    /// nothing; exactly 90 days is accepted.
    #[tokio::test]
    async fn issue1350_issue_refuses_a_grant_longer_than_90_days() -> anyhow::Result<()> {
        let (state, _dir) = owner_state().await?;
        let app = grants_router(Arc::clone(&state), false);
        let own = hex::encode(state.agent.agent_id().as_bytes());
        let body = |window: serde_json::Value| {
            let mut b = serde_json::json!({
                "grantee_agent": "c3".repeat(32),
                "agents": [own.clone()],
                "caps": ["dm"],
                "include_names": false,
            });
            if let (Some(obj), Some(more)) = (b.as_object_mut(), window.as_object()) {
                for (k, v) in more {
                    obj.insert(k.clone(), v.clone());
                }
            }
            b.to_string()
        };
        let max = MAX_SHARE_GRANT_LIFETIME_SECS;
        assert_eq!(max, 7_776_000, "90 days");
        for window in [
            serde_json::json!({"ttl_secs": max + 1}),
            serde_json::json!({"not_before": 1_000, "expiry": 1_000 + max + 1}),
            serde_json::json!({"ttl_secs": 365 * 86_400}),
        ] {
            let (status, json) =
                send(&app, owner_req("POST", "/grants", &body(window.clone()))?).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{window}: {json}");
            assert!(
                json["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("90 days"),
                "{window}: {json}"
            );
        }
        let (status, json) = send(&app, owner_req("GET", "/grants", "")?).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json["grants"],
            serde_json::json!([]),
            "nothing stored: {json}"
        );
        let (status, json) = send(
            &app,
            owner_req(
                "POST",
                "/grants",
                &body(serde_json::json!({"ttl_secs": max})),
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "exactly 90 days: {json}");
        Ok(())
    }

    /// WHY (#1350): `POST /grants/:id/renew` signs a NEW grant with the
    /// same grantee, agents and caps, valid from now for at most 90 days,
    /// and leaves the old grant active, so the grantee has no gap. An
    /// unknown id is 404; a revoked grant, `ttl_secs` 0 or above 90 days,
    /// and a malformed body are 400.
    #[tokio::test]
    async fn issue1350_renew_issues_a_new_grant_with_no_gap() -> anyhow::Result<()> {
        let (state, _dir) = owner_state().await?;
        let app = grants_router(Arc::clone(&state), false);
        let own = hex::encode(state.agent.agent_id().as_bytes());
        let issue = serde_json::json!({
            "grantee_agent": "c4".repeat(32),
            "agents": [own.clone()],
            "caps": ["dm", {"connect": {"ports": [22, 80]}}],
            "ttl_secs": 3_600,
            "include_names": false,
        })
        .to_string();
        let (status, json) = send(&app, owner_req("POST", "/grants", &issue)?).await?;
        assert_eq!(status, StatusCode::OK, "{json}");
        let old_id = json["grant"]["grant_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("grant_id: {json}"))?
            .to_string();
        let old_raw = parse_id32("id", &old_id).map_err(|e| anyhow::anyhow!(e))?;
        let store = state
            .agent
            .share_grant_store()
            .ok_or_else(|| anyhow::anyhow!("store"))?;
        let old = store
            .issued(&old_raw)
            .ok_or_else(|| anyhow::anyhow!("old held"))?;

        let before = unix_now_secs();
        let renew_path = format!("/grants/{old_id}/renew");
        let (status, json) = send(&app, owner_req("POST", &renew_path, "")?).await?;
        let after = unix_now_secs();
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["renews"], serde_json::json!(old_id), "{json}");
        let new_id = json["grant"]["grant_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("new grant_id: {json}"))?;
        assert_ne!(new_id, old_id, "a renewal is a new grant");
        let new = store
            .issued(&parse_id32("id", new_id).map_err(|e| anyhow::anyhow!(e))?)
            .ok_or_else(|| anyhow::anyhow!("renewal held"))?;
        new.verify()?;
        assert_eq!(new.grantee, old.grantee);
        assert_eq!(new.agents, old.agents);
        assert_eq!(new.caps, old.caps);
        assert!(
            before <= new.not_before && new.not_before <= after,
            "{new:?}"
        );
        assert_eq!(
            new.expiry - new.not_before,
            MAX_SHARE_GRANT_LIFETIME_SECS,
            "default renewal is 90 days"
        );
        // No gap: the renewal starts while the old grant is active, and
        // both are active at the moment the renewal starts.
        assert!(new.not_before < old.expiry);
        assert!(old.is_active_at(new.not_before) && new.is_active_at(new.not_before));
        assert!(
            new.is_active_at(old.expiry),
            "still active after the old expiry"
        );
        assert!(store.issued(&old_raw).is_some(), "the old grant is kept");

        // An explicit shorter lifetime.
        let (status, json) = send(
            &app,
            owner_req(
                "POST",
                &renew_path,
                r#"{"ttl_secs":600,"include_names":false}"#,
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            json["grant"]["expiry"].as_u64().unwrap_or_default()
                - json["grant"]["not_before"].as_u64().unwrap_or_default(),
            600
        );

        // Refusals.
        for (body, want) in [
            (r#"{"ttl_secs":0}"#.to_string(), StatusCode::BAD_REQUEST),
            (
                format!(r#"{{"ttl_secs":{}}}"#, MAX_SHARE_GRANT_LIFETIME_SECS + 1),
                StatusCode::BAD_REQUEST,
            ),
            (r#"{"ttl":60}"#.to_string(), StatusCode::BAD_REQUEST),
            ("{not json".to_string(), StatusCode::BAD_REQUEST),
        ] {
            let (status, json) = send(&app, owner_req("POST", &renew_path, &body)?).await?;
            assert_eq!(status, want, "{body}: {json}");
        }
        let (status, json) = send(
            &app,
            owner_req("POST", &format!("/grants/{}/renew", "dd".repeat(32)), "")?,
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown id: {json}");
        let (status, _) = send(&app, owner_req("POST", "/grants/not-hex/renew", "")?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, json) =
            send(&app, owner_req("DELETE", &format!("/grants/{old_id}"), "")?).await?;
        assert_eq!(status, StatusCode::OK, "{json}");
        let held = store.grants(GrantRole::Issued).len();
        let (status, json) = send(&app, owner_req("POST", &renew_path, "")?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "revoked: {json}");
        assert!(
            json["error"]
                .as_str()
                .unwrap_or_default()
                .contains("revoked"),
            "{json}"
        );
        assert_eq!(
            store.grants(GrantRole::Issued).len(),
            held,
            "no grant signed"
        );
        Ok(())
    }
}
