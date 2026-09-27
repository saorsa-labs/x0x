//! Route handlers (`category: "notes"` in `src/api/mod.rs`): the ADR 0081
//! notes store — create, list, read and save.
//!
//! Notes live in the group's `notes` store, opened through the ordinary
//! group-store path (`POST /groups/:id/stores`), so they are sealed exactly
//! like the Wiki store and #914 task lists. Riders never reach notes
//! (ADR 0075 Q4). The three-way merge from an older `base_version` is a
//! later slice: a stale base is refused with 409 `base_version_stale`.

use super::super::rider_auth::ActorContext;
use super::super::state::AppState;
use super::super::{api_error, forbidden};
use super::stores::{create_group_kv_store, find_store_group, CreateGroupStoreRequest};
use crate as x0x;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use x0x::groups::{GroupInfo, GroupRole, GroupWriteAccess};
use x0x::identity::AgentId;
use x0x::kv::encrypted::AuthorSigning;
use x0x::notes::store::WriterCheck;
use x0x::notes::{NoteError, NotesStore, NOTES_STORE_NAME};

type NotesResponse = (StatusCode, Json<serde_json::Value>);

/// Request body for `POST /groups/:id/notes`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateNoteRequest {
    title: String,
}

/// Request body for `PUT /groups/:id/notes/:note`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct SaveNoteRequest {
    text: String,
    base_version: String,
}

/// The group's current writer rule: an active member, and an admin when
/// the group's write access is admin-only (the same rule the group KV
/// contexts enforce). A withdrawn or fork-quarantined group has no writers.
fn group_writer_check(info: &GroupInfo) -> WriterCheck {
    if info.withdrawn || info.is_fork_quarantined() {
        return Arc::new(|_: &AgentId| false);
    }
    let writers: HashMap<[u8; 32], GroupRole> = info
        .active_members()
        .filter_map(|member| {
            let mut id = [0u8; 32];
            hex::decode_to_slice(&member.agent_id, &mut id).ok()?;
            Some((id, member.role))
        })
        .collect();
    let access = info.policy.write_access;
    Arc::new(move |agent: &AgentId| match access {
        GroupWriteAccess::MembersOnly => writers.contains_key(&agent.0),
        GroupWriteAccess::AdminOnly => writers
            .get(&agent.0)
            .is_some_and(|role| role.at_least(GroupRole::Admin)),
        GroupWriteAccess::ModeratedPublic => false,
    })
}

/// Map a notes error to its HTTP status and `{error: <reason>, message}`.
fn note_error(error: &NoteError) -> NotesResponse {
    let status = match error {
        NoteError::EngineFault { .. } | NoteError::Degraded { .. } => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        NoteError::BaseVersionUnknown | NoteError::BaseVersionStale | NoteError::SeqConflict(_) => {
            StatusCode::CONFLICT
        }
        NoteError::InvalidVersion(_) | NoteError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
        NoteError::NoteTooLarge { .. } | NoteError::StoreFull { .. } => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        NoteError::NotFound => StatusCode::NOT_FOUND,
        NoteError::Forbidden(_) => StatusCode::FORBIDDEN,
        NoteError::PeerIdExhausted | NoteError::Signing(_) | NoteError::Store(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    let mut body = serde_json::json!({
        "ok": false,
        "error": error.reason(),
        "message": error.to_string(),
    });
    match error {
        NoteError::StoreFull {
            current,
            projected,
            budget,
        } => {
            body["current"] = serde_json::json!(current);
            body["projected"] = serde_json::json!(projected);
            body["budget"] = serde_json::json!(budget);
        }
        NoteError::NoteTooLarge {
            current,
            attempted,
            cap,
        } => {
            body["current"] = serde_json::json!(current);
            body["attempted"] = serde_json::json!(attempted);
            body["cap"] = serde_json::json!(cap);
        }
        _ => {}
    }
    (status, Json(body))
}

fn ok_json(status: StatusCode, value: impl serde::Serialize) -> NotesResponse {
    let mut body = serde_json::to_value(value).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = body.as_object_mut() {
        obj.insert("ok".to_string(), serde_json::Value::Bool(true));
    }
    (status, Json(body))
}

/// Open (idempotently) the group's `notes` store and snapshot its writer
/// rule.
async fn open_notes_store(
    state: &Arc<AppState>,
    group_id: &str,
    actor: &ActorContext,
) -> Result<(x0x::KvStoreHandle, WriterCheck, AuthorSigning), NotesResponse> {
    if matches!(actor, ActorContext::Rider { .. }) {
        return Err(forbidden("rider tokens have no note access"));
    }
    let (topic, writers) = {
        let groups = state.named_groups.read().await;
        let (_, info) = find_store_group(&groups, group_id)?;
        let (_, topic) =
            x0x::kv::encrypted::group_store_identity(info.stable_group_id(), NOTES_STORE_NAME);
        (topic, group_writer_check(info))
    };
    let existing = state.kv_stores.read().await.get(&topic).cloned();
    let handle = match existing {
        Some(handle) => handle,
        None => {
            let (status, body) = create_group_kv_store(
                State(Arc::clone(state)),
                Path(group_id.to_string()),
                Extension(actor.clone()),
                Json(CreateGroupStoreRequest::named(NOTES_STORE_NAME)),
            )
            .await;
            if !status.is_success() {
                return Err((status, body));
            }
            state
                .kv_stores
                .read()
                .await
                .get(&topic)
                .cloned()
                .ok_or_else(|| {
                    api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "notes store did not register",
                    )
                })?
        }
    };
    let signing = AuthorSigning::from_keypair(state.agent.identity().agent_keypair())
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")))?;
    Ok((handle, writers, signing))
}

/// POST /groups/:id/notes
pub(in crate::server) async fn create_group_note(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<CreateNoteRequest>,
) -> NotesResponse {
    let (handle, writers, signing) = match open_notes_store(&state, &id, &actor).await {
        Ok(opened) => opened,
        Err(response) => return response,
    };
    let store = NotesStore::new(&handle, &state.notes, &signing, writers);
    match store.create(&req.title).await {
        Ok(note) => ok_json(StatusCode::CREATED, note),
        Err(e) => note_error(&e),
    }
}

/// GET /groups/:id/notes
pub(in crate::server) async fn list_group_notes(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Extension(actor): Extension<ActorContext>,
) -> NotesResponse {
    let (handle, writers, signing) = match open_notes_store(&state, &id, &actor).await {
        Ok(opened) => opened,
        Err(response) => return response,
    };
    let store = NotesStore::new(&handle, &state.notes, &signing, writers);
    match store.list().await {
        Ok(notes) => ok_json(StatusCode::OK, serde_json::json!({ "notes": notes })),
        Err(e) => note_error(&e),
    }
}

/// GET /groups/:id/notes/:note
pub(in crate::server) async fn get_group_note(
    State(state): State<Arc<AppState>>,
    Path((id, note)): Path<(String, String)>,
    Extension(actor): Extension<ActorContext>,
) -> NotesResponse {
    let (handle, writers, signing) = match open_notes_store(&state, &id, &actor).await {
        Ok(opened) => opened,
        Err(response) => return response,
    };
    let store = NotesStore::new(&handle, &state.notes, &signing, writers);
    match store.read(&note).await {
        Ok(doc) => ok_json(StatusCode::OK, doc),
        Err(e) => note_error(&e),
    }
}

/// PUT /groups/:id/notes/:note
pub(in crate::server) async fn save_group_note(
    State(state): State<Arc<AppState>>,
    Path((id, note)): Path<(String, String)>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<SaveNoteRequest>,
) -> NotesResponse {
    let (handle, writers, signing) = match open_notes_store(&state, &id, &actor).await {
        Ok(opened) => opened,
        Err(response) => return response,
    };
    let store = NotesStore::new(&handle, &state.notes, &signing, writers);
    match store.save(&note, &req.text, &req.base_version).await {
        // #976 convention: saved locally but not yet published is 202.
        Ok(outcome) if outcome.published => ok_json(StatusCode::OK, outcome),
        Ok(outcome) => ok_json(StatusCode::ACCEPTED, outcome),
        Err(e) => note_error(&e),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn test_network_config() -> x0x::network::NetworkConfig {
        x0x::network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..x0x::network::NetworkConfig::default()
        }
    }

    async fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_identity_dir(&data_dir)
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key(x0x::identity::AgentKeypair::generate().expect("agent key"))
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_peer_cache_disabled()
                .with_contact_store_path(data_dir.join("contacts.json"))
                .with_network_config(test_network_config())
                .build()
                .await
                .expect("agent"),
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            &data_dir, agent,
        )
        .await
        .expect("state");
        (state, dir)
    }

    /// An MlsEncrypted GSS group created by the daemon agent.
    async fn seed_group(state: &AppState, group_key: &str) {
        let mut info = GroupInfo::new(
            "notes-group".to_string(),
            String::new(),
            state.agent.agent_id(),
            group_key.to_string(),
        );
        info.migrate_from_v1();
        let _ = info.rotate_shared_secret();
        state
            .named_groups
            .write()
            .await
            .insert(group_key.to_string(), info);
    }

    fn owner() -> Extension<ActorContext> {
        Extension(ActorContext::Owner { durable: true })
    }

    /// WHY: the four notes routes are the slice's whole REST surface. A
    /// created note lists, reads back empty, saves against its version, and
    /// reads back the saved text; the store they use is the group's sealed
    /// `notes` store; a stale base is 409 `base_version_stale`.
    #[tokio::test]
    async fn notes_routes_create_list_read_save_round_trip() {
        let (state, _dir) = test_state().await;
        let group_key = "a1".repeat(16);
        seed_group(&state, &group_key).await;

        let (code, created) = create_group_note(
            State(Arc::clone(&state)),
            Path(group_key.clone()),
            owner(),
            Json(CreateNoteRequest {
                title: "Agenda".into(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{created:?}");
        let note_id = created.0["note_id"].as_str().expect("id").to_string();
        let v0 = created.0["version"].as_str().expect("version").to_string();
        assert_eq!(created.0["text"], "");

        // The backing store is the group's encrypted `notes` store.
        let stable = {
            let groups = state.named_groups.read().await;
            groups
                .get(&group_key)
                .expect("group")
                .stable_group_id()
                .to_string()
        };
        let (_, topic) = x0x::kv::encrypted::group_store_identity(&stable, NOTES_STORE_NAME);
        let handle = state
            .kv_stores
            .read()
            .await
            .get(&topic)
            .cloned()
            .expect("notes store registered");
        assert!(handle.is_encrypted().await, "notes are sealed like #914");

        let (code, listed) =
            list_group_notes(State(Arc::clone(&state)), Path(group_key.clone()), owner()).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(listed.0["notes"][0]["note_id"], note_id.as_str());
        assert_eq!(listed.0["notes"][0]["title"], "Agenda");

        let (code, saved) = save_group_note(
            State(Arc::clone(&state)),
            Path((group_key.clone(), note_id.clone())),
            owner(),
            Json(SaveNoteRequest {
                text: "1. budget".into(),
                base_version: v0.clone(),
            }),
        )
        .await;
        assert!(code.is_success(), "{saved:?}");
        assert_eq!(saved.0["text"], "1. budget");
        assert_eq!(saved.0["records_written"], 1);

        let (code, read) = get_group_note(
            State(Arc::clone(&state)),
            Path((group_key.clone(), note_id.clone())),
            owner(),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(read.0["text"], "1. budget");
        assert_eq!(read.0["title"], "Agenda");

        let (code, stale) = save_group_note(
            State(Arc::clone(&state)),
            Path((group_key.clone(), note_id.clone())),
            owner(),
            Json(SaveNoteRequest {
                text: "lost?".into(),
                base_version: v0,
            }),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT);
        assert_eq!(stale.0["error"], "base_version_stale");

        let (code, missing) = get_group_note(
            State(Arc::clone(&state)),
            Path((group_key.clone(), "0".repeat(32))),
            owner(),
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND, "{missing:?}");
    }

    /// WHY (ADR 0075 Q4, carried by 0081): riders never reach notes, even
    /// if a route slipped past the middleware allow-list.
    #[tokio::test]
    async fn notes_routes_refuse_riders() {
        let (state, _dir) = test_state().await;
        let group_key = "a2".repeat(16);
        seed_group(&state, &group_key).await;
        let rider = ActorContext::Rider {
            sub_agent_id: "cd".repeat(32),
            token_id: 1,
            token_hash: "ef".repeat(32),
            groups: vec![group_key.clone()],
        };
        let (code, _) =
            list_group_notes(State(Arc::clone(&state)), Path(group_key), Extension(rider)).await;
        assert_eq!(code, StatusCode::FORBIDDEN);
    }

    /// The HTTP mapping of the ADR's error codes.
    #[test]
    fn note_errors_map_to_the_adr_statuses() {
        let full = note_error(&NoteError::StoreFull {
            current: 10,
            projected: 20,
            budget: 12,
        });
        assert_eq!(full.0, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(full.1 .0["error"], "notes_store_full");
        assert_eq!(full.1 .0["current"], 10);
        assert_eq!(full.1 .0["budget"], 12);
        let big = note_error(&NoteError::NoteTooLarge {
            current: 1,
            attempted: 2,
            cap: 3,
        });
        assert_eq!(big.0, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(big.1 .0["error"], "note_too_large");
        let degraded = note_error(&NoteError::Degraded {
            note_id: "n".into(),
        });
        assert_eq!(degraded.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(degraded.1 .0["error"], "note_engine_fault");
        let unknown = note_error(&NoteError::BaseVersionUnknown);
        assert_eq!(unknown.0, StatusCode::CONFLICT);
        assert_eq!(unknown.1 .0["error"], "base_version_unknown");
    }
}
