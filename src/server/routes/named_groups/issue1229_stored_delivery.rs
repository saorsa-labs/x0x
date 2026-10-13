//! #1229: `GET /groups/:id/messages` re-checks the author at delivery.
//! A row that was stored while the sender was allowed must disappear
//! after that sender is Blocked or revoked. A third author stays.

use super::tests::secure_endpoint_test_state;
use super::{build_group_public_history_record, get_group_public_messages};
use crate as x0x;
use crate::server::state::AppState;
use anyhow::Result;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt as _;
use x0x::contacts::TrustLevel;

const GROUP: &str = "issue1229-public";
const TOKEN: &str = "test-token";

fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/groups/:id/messages", get(get_group_public_messages))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(state)
}

async fn message_bodies(app: &axum::Router) -> Result<BTreeSet<String>> {
    let request = Request::get(format!("/groups/{GROUP}/messages"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(status, StatusCode::OK, "{json}");
    let bodies = json["messages"]
        .as_array()
        .unwrap_or_else(|| panic!("messages array missing: {json}"))
        .iter()
        .map(|message| {
            message["body"]
                .as_str()
                .unwrap_or_else(|| panic!("message body missing: {message}"))
                .to_string()
        })
        .collect();
    Ok(bodies)
}

fn signed(
    group_id: &str,
    keypair: &x0x::identity::AgentKeypair,
    body: &str,
    timestamp: u64,
) -> x0x::groups::GroupPublicMessage {
    x0x::groups::GroupPublicMessage::sign(
        group_id.to_string(),
        "state".into(),
        1,
        keypair,
        None,
        x0x::groups::GroupPublicMessageKind::Chat,
        body.to_string(),
        timestamp,
        None,
        None,
        None,
    )
    .expect("sign public message")
}

#[tokio::test]
async fn issue1229_cached_and_stored_messages_hide_blocked_or_revoked_authors() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let info = x0x::groups::GroupInfo::with_policy(
        "issue1229".into(),
        String::new(),
        state.agent.agent_id(),
        GROUP.into(),
        x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    let stable = info.stable_group_id().to_string();
    state.named_groups.write().await.insert(GROUP.into(), info);

    let blocked_kp = x0x::identity::AgentKeypair::generate()?;
    let revoked_kp = x0x::identity::AgentKeypair::generate()?;
    let kept_kp = x0x::identity::AgentKeypair::generate()?;
    let blocked = signed(&stable, &blocked_kp, "from-cache", 1);
    let revoked = signed(&stable, &revoked_kp, "from-history", 2);
    let kept = signed(&stable, &kept_kp, "kept", 3);

    state
        .public_messages
        .write()
        .await
        .insert(stable.clone(), vec![blocked, kept.clone()]);

    let store = state.agent.history().expect("history").store();
    for message in [&revoked, &kept] {
        let record = build_group_public_history_record(&state, message).expect("history record");
        store.insert(&record)?;
    }

    let app = router(Arc::clone(&state));
    let before = message_bodies(&app).await?;
    assert_eq!(
        before,
        BTreeSet::from([
            "from-cache".to_string(),
            "from-history".to_string(),
            "kept".to_string()
        ]),
        "all three authors are served before a refusal"
    );

    let blocked_id = blocked_kp.agent_id();
    state
        .contacts
        .write()
        .await
        .set_trust(&blocked_id, TrustLevel::Blocked);
    let revocation = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(revoked_kp.agent_id()),
        revoked_kp.public_key(),
        revoked_kp.secret_key(),
        x0x::groups::owner_cert::restore_clock_now(),
        Some("issue1229".to_string()),
    )?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(revocation, None)?;

    let after = message_bodies(&app).await?;
    assert_eq!(
        after,
        BTreeSet::from(["kept".to_string()]),
        "a Blocked cache author and a revoked history author must not be served; the other author stays"
    );
    Ok(())
}
