//! #1229: history reads and direct SSE backfill re-check the sender.
//!
//! `/history`, point lookup, and search hide a refused author. Direct SSE
//! backfill also hides a revoked originating machine and a revoked binding,
//! and it checks each row when that event is emitted.

#![cfg(test)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use futures::StreamExt as _;
use tower::ServiceExt as _;

use crate::contacts::TrustLevel;
use crate::history::{HistoryRecord, Scope};
use crate::identity::{AgentKeypair, MachineKeypair};
use crate::revocation::{AgentMachineBinding, RevocationRecord, RevokedSubject};
use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
use crate::server::state::AppState;

const TOKEN: &str = "test-token";

fn history_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route(
            "/history",
            get(crate::server::routes::history::history_list),
        )
        .route(
            "/history/message/:msg_id",
            get(crate::server::routes::history::history_message),
        )
        .route(
            "/history/search",
            get(crate::server::routes::history::history_search),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(state)
}

fn text_row(
    scope: Scope,
    author: Option<String>,
    machine: Option<String>,
    body: &str,
    seen_at_ms: i64,
) -> HistoryRecord {
    let payload = body.as_bytes().to_vec();
    HistoryRecord {
        msg_id: HistoryRecord::compute_msg_id(None, &payload),
        scope,
        author_agent: author,
        author_machine: machine,
        author_pubkey: None,
        sent_at_ms: seen_at_ms,
        seen_at_ms,
        direction: crate::history::Direction::Inbound,
        content_type: "text/plain".to_string(),
        payload,
        signed_artifact: None,
        signature: None,
        sig_context: None,
        provenance: crate::history::Provenance::VerifiedEnvelope,
        replace_key: None,
        thread_root: None,
        thread_parent: None,
        ingress_sender_agent: None,
        logical_request_id: None,
    }
}

async fn get_json(app: &axum::Router, path: &str) -> Result<(StatusCode, serde_json::Value)> {
    let request = Request::get(path)
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await?;
    let json = serde_json::from_slice(&bytes)?;
    Ok((status, json))
}

fn record_bodies(json: &serde_json::Value) -> Result<BTreeSet<String>> {
    let records = json["records"]
        .as_array()
        .context("history records array missing")?;
    records
        .iter()
        .map(|row| {
            let payload = row["payload"].as_str().context("history payload missing")?;
            let bytes = BASE64
                .decode(payload)
                .context("history payload is base64")?;
            String::from_utf8(bytes).context("history payload is utf-8")
        })
        .collect()
}

fn hex_id(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

async fn self_revoke_agent(state: &AppState, keypair: &AgentKeypair) -> Result<()> {
    let revocation = RevocationRecord::sign(
        RevokedSubject::Agent(keypair.agent_id()),
        keypair.public_key(),
        keypair.secret_key(),
        crate::groups::owner_cert::restore_clock_now(),
        Some("issue1229".to_string()),
    )?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(revocation, None)?;
    Ok(())
}

async fn self_revoke_machine(state: &AppState, keypair: &MachineKeypair) -> Result<()> {
    let revocation = RevocationRecord::sign(
        RevokedSubject::Machine(keypair.machine_id()),
        keypair.public_key(),
        keypair.secret_key(),
        crate::groups::owner_cert::restore_clock_now(),
        Some("issue1229-machine".to_string()),
    )?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(revocation, None)?;
    Ok(())
}

#[tokio::test]
async fn issue1229_history_reads_hide_refused_authors() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let blocked_kp = AgentKeypair::generate()?;
    let revoked_kp = AgentKeypair::generate()?;
    let contact_kp = AgentKeypair::generate()?;
    let kept_kp = AgentKeypair::generate()?;
    let machine_agent = AgentKeypair::generate()?;
    let binding_agent = AgentKeypair::generate()?;
    let revoked_machine = MachineKeypair::generate()?;
    let binding_machine = MachineKeypair::generate()?;
    let topic = Scope::Topic("issue1229-hist".into());
    let dm = Scope::Dm(hex_id(kept_kp.agent_id().as_bytes()));
    let store = state.agent.history().context("history")?.store();
    store.insert(&text_row(
        topic.clone(),
        Some(hex_id(blocked_kp.agent_id().as_bytes())),
        None,
        "topic blocked needle",
        1,
    ))?;
    store.insert(&text_row(
        topic.clone(),
        Some(hex_id(revoked_kp.agent_id().as_bytes())),
        None,
        "topic revoked needle",
        2,
    ))?;
    store.insert(&text_row(
        topic.clone(),
        Some(hex_id(contact_kp.agent_id().as_bytes())),
        None,
        "topic contact needle",
        3,
    ))?;
    store.insert(&text_row(
        topic.clone(),
        Some(hex_id(kept_kp.agent_id().as_bytes())),
        None,
        "topic kept needle",
        4,
    ))?;
    store.insert(&text_row(topic, None, None, "topic none needle", 5))?;
    store.insert(&text_row(
        dm.clone(),
        Some(hex_id(machine_agent.agent_id().as_bytes())),
        Some(hex_id(revoked_machine.machine_id().as_bytes())),
        "dm machine needle",
        6,
    ))?;
    store.insert(&text_row(
        dm.clone(),
        Some(hex_id(binding_agent.agent_id().as_bytes())),
        Some(hex_id(binding_machine.machine_id().as_bytes())),
        "dm binding needle",
        7,
    ))?;
    store.insert(&text_row(
        dm.clone(),
        Some(hex_id(blocked_kp.agent_id().as_bytes())),
        None,
        "dm blocked needle",
        8,
    ))?;
    store.insert(&text_row(
        dm.clone(),
        Some(hex_id(kept_kp.agent_id().as_bytes())),
        None,
        "dm kept needle",
        9,
    ))?;

    let app = history_router(Arc::clone(&state));
    let (status, before) = get_json(&app, "/history?scope=topic:issue1229-hist&limit=20").await?;
    assert_eq!(status, StatusCode::OK, "{before}");
    assert_eq!(
        record_bodies(&before)?,
        BTreeSet::from([
            "topic blocked needle".to_string(),
            "topic contact needle".to_string(),
            "topic kept needle".to_string(),
            "topic none needle".to_string(),
            "topic revoked needle".to_string(),
        ])
    );
    let kept_id = before["records"]
        .as_array()
        .context("records")?
        .iter()
        .find(|row| {
            row["payload"]
                .as_str()
                .is_some_and(|payload| payload_is(payload, "topic kept needle"))
        })
        .and_then(|row| row["msg_id"].as_str())
        .context("kept msg_id")?
        .to_string();
    let revoked_id = before["records"]
        .as_array()
        .context("records")?
        .iter()
        .find(|row| {
            row["payload"]
                .as_str()
                .is_some_and(|payload| payload_is(payload, "topic revoked needle"))
        })
        .and_then(|row| row["msg_id"].as_str())
        .context("revoked msg_id")?
        .to_string();

    state
        .contacts
        .write()
        .await
        .set_trust(&blocked_kp.agent_id(), TrustLevel::Blocked);
    self_revoke_agent(&state, &revoked_kp).await?;
    state
        .contacts
        .write()
        .await
        .revoke(&contact_kp.agent_id(), "issue1229");
    self_revoke_machine(&state, &revoked_machine).await?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .union_bundle_retired(&[AgentMachineBinding {
            agent: binding_agent.agent_id(),
            machine: binding_machine.machine_id(),
            move_epoch: 1,
        }]);

    let (status, topic_after) =
        get_json(&app, "/history?scope=topic:issue1229-hist&limit=20").await?;
    assert_eq!(status, StatusCode::OK, "{topic_after}");
    assert_eq!(
        record_bodies(&topic_after)?,
        BTreeSet::from([
            "topic kept needle".to_string(),
            "topic none needle".to_string(),
        ]),
        "history hides Blocked, revoked, and contact-revoked authors"
    );
    let dm_scope = format!(
        "/history?scope=dm:{}&limit=20",
        hex_id(kept_kp.agent_id().as_bytes())
    );
    let (status, dm_after) = get_json(&app, &dm_scope).await?;
    assert_eq!(status, StatusCode::OK, "{dm_after}");
    assert_eq!(
        record_bodies(&dm_after)?,
        BTreeSet::from(["dm kept needle".to_string()]),
        "DM history hides a revoked machine, a revoked binding, and a Blocked author"
    );

    let (hidden_status, _) = get_json(&app, &format!("/history/message/{revoked_id}")).await?;
    assert_eq!(hidden_status, StatusCode::NOT_FOUND);
    let (kept_status, kept_message) =
        get_json(&app, &format!("/history/message/{kept_id}")).await?;
    assert_eq!(kept_status, StatusCode::OK, "{kept_message}");
    let kept_payload = kept_message["record"]["payload"]
        .as_str()
        .context("point-lookup payload")?;
    assert!(payload_is(kept_payload, "topic kept needle"));

    let (search_status, search) = get_json(&app, "/history/search?q=needle&limit=20").await?;
    assert_eq!(search_status, StatusCode::OK, "{search}");
    assert_eq!(
        record_bodies(&search)?,
        BTreeSet::from([
            "dm kept needle".to_string(),
            "topic kept needle".to_string(),
            "topic none needle".to_string(),
        ]),
        "search hides the same refused authors"
    );

    state
        .contacts
        .write()
        .await
        .set_trust(&blocked_kp.agent_id(), TrustLevel::Known);
    let (status, restored) = get_json(&app, "/history?scope=topic:issue1229-hist&limit=20").await?;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert_eq!(
        record_bodies(&restored)?,
        BTreeSet::from([
            "topic blocked needle".to_string(),
            "topic kept needle".to_string(),
            "topic none needle".to_string(),
        ]),
        "clearing Blocked restores the history row"
    );
    Ok(())
}

fn payload_is(encoded: &str, body: &str) -> bool {
    BASE64
        .decode(encoded)
        .ok()
        .is_some_and(|bytes| bytes == body.as_bytes())
}

fn sse_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/direct/events", get(crate::server::sse::direct_events_sse))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(state)
}

async fn read_sse_until_live(app: &axum::Router) -> Result<String> {
    let request = Request::get("/direct/events?backfill=20")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())?;
    let response = app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let mut text = String::new();
    loop {
        let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .context("direct SSE timed out")?
            .context("direct SSE ended before live")?
            .context("direct SSE frame")?;
        text.push_str(&String::from_utf8_lossy(&chunk));
        if text.contains("event: live") {
            break;
        }
    }
    Ok(text)
}

fn insert_dm(
    store: &crate::history::store::Store,
    peer: &str,
    author: &AgentKeypair,
    machine: Option<&MachineKeypair>,
    body: &str,
    seen_at_ms: i64,
) -> Result<()> {
    store.insert(&text_row(
        Scope::Dm(peer.to_string()),
        Some(hex_id(author.agent_id().as_bytes())),
        machine.map(|kp| hex_id(kp.machine_id().as_bytes())),
        body,
        seen_at_ms,
    ))?;
    Ok(())
}

#[tokio::test]
async fn issue1229_direct_sse_backfill_hides_refused_senders() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let blocked_kp = AgentKeypair::generate()?;
    let revoked_kp = AgentKeypair::generate()?;
    let contact_kp = AgentKeypair::generate()?;
    let machine_agent = AgentKeypair::generate()?;
    let binding_agent = AgentKeypair::generate()?;
    let kept_kp = AgentKeypair::generate()?;
    let revoked_machine = MachineKeypair::generate()?;
    let binding_machine = MachineKeypair::generate()?;
    let store = state.agent.history().context("history")?.store();
    let peer = hex_id(kept_kp.agent_id().as_bytes());
    insert_dm(store, &peer, &blocked_kp, None, "sse-blocked", 1)?;
    insert_dm(store, &peer, &revoked_kp, None, "sse-revoked", 2)?;
    insert_dm(store, &peer, &contact_kp, None, "sse-contact", 3)?;
    insert_dm(
        store,
        &peer,
        &machine_agent,
        Some(&revoked_machine),
        "sse-machine",
        4,
    )?;
    insert_dm(
        store,
        &peer,
        &binding_agent,
        Some(&binding_machine),
        "sse-binding",
        5,
    )?;
    insert_dm(store, &peer, &kept_kp, None, "sse-kept", 6)?;

    state
        .contacts
        .write()
        .await
        .set_trust(&blocked_kp.agent_id(), TrustLevel::Blocked);
    self_revoke_agent(&state, &revoked_kp).await?;
    state
        .contacts
        .write()
        .await
        .revoke(&contact_kp.agent_id(), "issue1229");
    self_revoke_machine(&state, &revoked_machine).await?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .union_bundle_retired(&[AgentMachineBinding {
            agent: binding_agent.agent_id(),
            machine: binding_machine.machine_id(),
            move_epoch: 1,
        }]);

    let app = sse_router(Arc::clone(&state));
    let text = read_sse_until_live(&app).await?;
    assert!(
        text.contains(&BASE64.encode(b"sse-kept")),
        "the clean author must be replayed: {text}"
    );
    for hidden in [
        "sse-blocked",
        "sse-revoked",
        "sse-contact",
        "sse-machine",
        "sse-binding",
    ] {
        assert!(
            !text.contains(&BASE64.encode(hidden.as_bytes())),
            "{hidden} must not be replayed: {text}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn issue1229_direct_sse_rechecks_when_each_event_is_emitted() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let author = AgentKeypair::generate()?;
    let store = state.agent.history().context("history")?.store();
    let peer = hex_id(author.agent_id().as_bytes());
    insert_dm(store, &peer, &author, None, "sse-first", 1)?;
    insert_dm(store, &peer, &author, None, "sse-second", 2)?;

    let app = sse_router(Arc::clone(&state));
    let request = Request::get("/direct/events?backfill=20")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())?;
    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .context("first SSE event timed out")?
        .context("first SSE event missing")?
        .context("first SSE frame")?;
    let first = String::from_utf8_lossy(&first);
    assert!(
        first.contains(&BASE64.encode(b"sse-first")),
        "the first row is emitted while the author is allowed: {first}"
    );
    assert!(
        !first.contains(&BASE64.encode(b"sse-second")),
        "the second row must not be decided before it is emitted: {first}"
    );

    state
        .contacts
        .write()
        .await
        .set_trust(&author.agent_id(), TrustLevel::Blocked);

    let mut rest = String::new();
    loop {
        let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .context("later SSE event timed out")?
            .context("SSE ended before live")?
            .context("later SSE frame")?;
        rest.push_str(&String::from_utf8_lossy(&chunk));
        if rest.contains("event: live") {
            break;
        }
    }
    assert!(
        !rest.contains(&BASE64.encode(b"sse-second")),
        "a Block applied between events must hide the remaining row: {rest}"
    );
    Ok(())
}
