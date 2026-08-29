//! ADR-0041 Tier-1 sync routes: `GET /sync/devices` and
//! `POST /sync/devices/enroll`, plus the [`SyncDaemonView`] adapter that
//! bridges the sync service to live `AppState` (this module is inside the
//! `server` subtree, so it may read the daemon state fields the library
//! module cannot).
//!
//! Both routes are owner-gated: the bearer-token middleware has already
//! authenticated the caller; an install with no owner key (`user.key`) has
//! no device set to serve or extend and answers `409`, mirroring
//! `GET /owner/agents`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde::Serialize;

use super::status::ApiResponse;
use crate::owner_sync::{OwnerEnrollment, SyncDaemonView, SyncProfileNames, SyncValue};
use crate::server::state::AppState;

/// Adapter over live daemon state for the sync service.
///
/// `profile_names` keeps a last-seen mirror: `apply_names` writes it
/// synchronously so the very next reconcile pass cannot re-mint a
/// pre-merge value (LWW flip-back), while the live `AppState` profile and
/// its persisted file catch up in a spawned task.
pub(in crate::server) struct DaemonView {
    state: Arc<AppState>,
    names: std::sync::RwLock<SyncProfileNames>,
}

impl DaemonView {
    pub(in crate::server) fn new(state: Arc<AppState>) -> Self {
        let names = match state.profile.try_read() {
            Ok(profile) => SyncProfileNames {
                human_name: profile.human_name.clone(),
                display_name: profile.display_name.clone(),
                machine_name: profile.machine_name.clone(),
            },
            Err(_) => SyncProfileNames::default(),
        };
        Self {
            state,
            names: std::sync::RwLock::new(names),
        }
    }
}

impl SyncDaemonView for DaemonView {
    fn profile_names(&self) -> SyncProfileNames {
        if let Ok(profile) = self.state.profile.try_read() {
            let fresh = SyncProfileNames {
                human_name: profile.human_name.clone(),
                display_name: profile.display_name.clone(),
                machine_name: profile.machine_name.clone(),
            };
            *self
                .names
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh.clone();
            return fresh;
        }
        // Lock contended: report the last-seen mirror (never a regression
        // to empty — a mint from a wrong default would fight the winner).
        self.names
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn home_pointer(&self) -> Option<SyncValue> {
        let owner = self.state.agent.identity().user_keypair()?.user_id();
        let groups = self.state.named_groups.try_read().ok()?;
        // Mirror of `routes::home::find_home` (same module subtree): any
        // group stamped as Home for this owner.
        groups
            .values()
            .find(|info| {
                info.home.is_some()
                    && info
                        .policy
                        .admission
                        .owner_certified_user_id()
                        .is_some_and(|u| *u == owner)
            })
            .map(|info| SyncValue::HomePointer {
                group_id: info.stable_group_id().to_string(),
                policy: info.policy.clone(),
                roster: info
                    .members_v2
                    .values()
                    .map(|m| crate::owner_sync::HomeRosterEntry {
                        agent_id: m.agent_id.clone(),
                        role: m.role,
                        state: m.state,
                    })
                    .collect(),
                primary_agent: info
                    .home
                    .as_ref()
                    .map(|h| h.primary_agent.clone())
                    .unwrap_or_default(),
                provisioned_at_ms: info
                    .home
                    .as_ref()
                    .map(|h| h.provisioned_at_ms)
                    .unwrap_or_default(),
            })
    }

    fn apply_names(
        &self,
        human_name: Option<String>,
        display_name: Option<String>,
        machine_name: Option<String>,
    ) {
        // 1. Synchronous mirror merge — closes the LWW flip-back window.
        {
            let mut names = self
                .names
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if human_name.is_some() {
                names.human_name = human_name.clone();
            }
            if display_name.is_some() {
                names.display_name = display_name.clone();
            }
            if machine_name.is_some() {
                names.machine_name = machine_name.clone();
            }
        }
        // 2. Async live-state + persistence catch-up. `None` args mean
        // "leave unchanged" (PUT /profile semantics); nothing to do when
        // all three are absent.
        if human_name.is_none() && display_name.is_none() && machine_name.is_none() {
            return;
        }
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let mut profile = state.profile.write().await;
            let mut changed = false;
            if let Some(human) = human_name {
                if profile.human_name != Some(human.clone()) {
                    profile.human_name = Some(human);
                    changed = true;
                }
            }
            if let Some(display) = display_name {
                if profile.display_name != Some(display.clone()) {
                    profile.display_name = Some(display.clone());
                    changed = true;
                }
            }
            if let Some(machine) = machine_name {
                if profile.machine_name != Some(machine.clone()) {
                    profile.machine_name = Some(machine);
                    changed = true;
                }
            }
            if !changed {
                return;
            }
            let snapshot = profile.clone();
            let path = state.profile_path.clone();
            drop(profile);
            // The announce self-name follows the merged display name
            // (mirrors PUT /profile).
            state.agent.set_self_name(snapshot.display_name.clone());
            if let Err(e) = snapshot.save_to(&path).await {
                tracing::warn!(
                    target: "x0x::owner_sync",
                    "failed to persist synced profile: {e}"
                );
            }
        });
    }
}

/// One enrolled device in the `GET /sync/devices` response.
#[derive(Debug, Serialize)]
pub(in crate::server) struct SyncDeviceEntry {
    machine_id: String,
    enrolled_at_ms: u64,
    last_session_ms: Option<u64>,
    last_session_ok: Option<bool>,
    #[serde(rename = "is_this_machine")]
    is_this_machine: bool,
}

/// GET /sync/devices response body.
#[derive(Debug, Serialize)]
pub(in crate::server) struct SyncDevicesData {
    owner_user_id: String,
    this_machine_id: String,
    devices: Vec<SyncDeviceEntry>,
}

/// GET /sync/devices — the owner device set plus last-sync status per
/// device (ADR-0041 Tier-1; GUI Settings › Sync panel).
///
/// `409` when no owner identity is configured (owner-gated).
pub(in crate::server) async fn get_sync_devices(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(sync) = state.owner_sync.as_ref() else {
        return error_response(StatusCode::CONFLICT, "no owner identity configured");
    };
    let Some(owner) = state.agent.identity().user_keypair() else {
        return error_response(StatusCode::CONFLICT, "no owner identity configured");
    };
    let this_machine = state.agent.machine_id();
    let statuses = sync.store().session_statuses().await;
    let mut devices: Vec<SyncDeviceEntry> = sync
        .store()
        .enrolled_devices()
        .await
        .into_iter()
        .map(|enrollment| {
            let status = statuses.get(&enrollment.machine_id);
            SyncDeviceEntry {
                machine_id: hex::encode(enrollment.machine_id),
                enrolled_at_ms: enrollment.enrolled_at_ms,
                last_session_ms: status.map(|s| s.last_session_ms),
                last_session_ok: status.map(|s| s.last_session_ok),
                is_this_machine: enrollment.machine_id == this_machine.0,
            }
        })
        .collect();
    devices.sort_by(|a, b| a.machine_id.cmp(&b.machine_id));
    let body = ApiResponse {
        ok: true,
        data: SyncDevicesData {
            owner_user_id: hex::encode(owner.user_id().0),
            this_machine_id: hex::encode(this_machine.0),
            devices,
        },
    };
    (
        StatusCode::OK,
        Json(serde_json::to_value(body).unwrap_or_default()),
    )
}

/// POST /sync/devices/enroll request body — `machine_id` optional;
/// omitted = enroll THIS machine.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct EnrollRequest {
    machine_id: Option<String>,
}

/// POST /sync/devices/enroll response body.
#[derive(Debug, Serialize)]
pub(in crate::server) struct EnrollData {
    machine_id: String,
    enrolled_at_ms: u64,
    device_count: usize,
}

/// POST /sync/devices/enroll — owner-key-sign a `DeviceEnrollment` for a
/// machine and add it to the local owner device set (owner-gated: the
/// daemon must hold the owner key; ADR-0043 enrollment direction).
///
/// The signature is verified again at every stream accept, so a corrupt or
/// foreign-key enrollment can never open the sync gate.
pub(in crate::server) async fn enroll_device(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(sync) = state.owner_sync.as_ref() else {
        return error_response(StatusCode::CONFLICT, "no owner identity configured");
    };
    let Some(owner_kp) = state.agent.identity().user_keypair() else {
        return error_response(StatusCode::CONFLICT, "no owner identity configured");
    };
    let machine = match req.machine_id.as_deref() {
        None => state.agent.machine_id(),
        Some(hex_id) => match decode_machine_id(hex_id) {
            Some(machine) => machine,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "machine_id must be 64 hex characters",
                );
            }
        },
    };
    let enrolled_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let enrollment = match OwnerEnrollment::sign(machine, owner_kp, enrolled_at_ms) {
        Ok(enrollment) => enrollment,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let machine_hex = hex::encode(enrollment.machine_id);
    sync.store().enroll(enrollment).await;
    let device_count = sync.store().enrolled_devices().await.len();
    // Enrollment is Tier-1-relevant state: kick an early sync pass.
    sync.kick();
    let body = ApiResponse {
        ok: true,
        data: EnrollData {
            machine_id: machine_hex,
            enrolled_at_ms,
            device_count,
        },
    };
    (
        StatusCode::OK,
        Json(serde_json::to_value(body).unwrap_or_default()),
    )
}

fn decode_machine_id(hex_id: &str) -> Option<crate::identity::MachineId> {
    let bytes = hex::decode(hex_id).ok()?;
    let fixed: [u8; 32] = bytes.try_into().ok()?;
    Some(crate::identity::MachineId(fixed))
}

fn error_response(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": message })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::routes::sync::DaemonView;

    /// WHY: the profile mirror must never regress to defaults while the
    /// AppState lock is contended — a default read would mint a record
    /// that fights the remote winner (LWW flip-back).
    #[tokio::test]
    async fn daemon_view_mirror_survives_lock_contention() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("test state");
        let view = DaemonView::new(Arc::clone(&state));
        view.apply_names(
            Some("David".into()),
            Some("primary-agent".into()),
            Some("laptop".into()),
        );
        // Contend the profile lock so the refresh path fails and the
        // last-seen mirror is served instead.
        let guard = state.profile.write().await;
        let names = view.profile_names();
        drop(guard);
        assert_eq!(names.human_name.as_deref(), Some("David"));
        assert_eq!(names.display_name.as_deref(), Some("primary-agent"));
        assert_eq!(names.machine_name.as_deref(), Some("laptop"));
    }

    /// Owned test state: user key (deterministic seed) + builder-issued
    /// agent certificate, so `secure_endpoint_test_state_at` wires the
    /// ADR-0041 sync service exactly like daemon startup.
    async fn owned_state(
        data_dir: &std::path::Path,
        owner_seed: [u8; 32],
    ) -> anyhow::Result<Arc<AppState>> {
        let user = crate::identity::UserKeypair::from_seed(&owner_seed)?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key_path(data_dir.join("agent.key"))
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(data_dir.join("contacts.json"))
                .build()
                .await?,
        );
        crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(data_dir, agent)
            .await
    }

    async fn response_json(
        response: axum::response::Response,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        use axum::body::to_bytes;
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&body)?))
    }

    /// WHY: `GET /sync/devices` / `POST /sync/devices/enroll` are wired and
    /// owner-gated — an ownerless install answers 409, an owned one lists
    /// and enrolls devices (the enrollment signature is re-verified at
    /// every stream accept).
    #[tokio::test]
    async fn sync_routes_wired() -> anyhow::Result<()> {
        use tower::ServiceExt;

        // Ownerless: 409 on both routes.
        let _dir = tempfile::tempdir()?;
        let (unowned, _guard) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let app = axum::Router::new()
            .route("/sync/devices", axum::routing::get(get_sync_devices))
            .route("/sync/devices/enroll", axum::routing::post(enroll_device))
            .with_state(Arc::clone(&unowned));
        let (status, body) = response_json(
            app.clone()
                .oneshot(
                    axum::http::Request::post("/sync/devices/enroll")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from("{}"))?,
                )
                .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::CONFLICT, "ownerless enroll: {body:?}");

        // Owned: enroll this machine, then list it.
        let dir2 = tempfile::tempdir()?;
        let state = owned_state(dir2.path(), [0x51; 32]).await?;
        let app = axum::Router::new()
            .route("/sync/devices", axum::routing::get(get_sync_devices))
            .route("/sync/devices/enroll", axum::routing::post(enroll_device))
            .with_state(Arc::clone(&state));
        let (status, body) = response_json(
            app.clone()
                .oneshot(
                    axum::http::Request::post("/sync/devices/enroll")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from("{}"))?,
                )
                .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "enroll this machine: {body:?}");
        assert!(body["ok"].as_bool().unwrap_or(false));
        let this_machine = hex::encode(state.agent.machine_id().0);
        assert_eq!(body["machine_id"].as_str(), Some(this_machine.as_str()));

        let (status, body) = response_json(
            app.oneshot(axum::http::Request::get("/sync/devices").body(axum::body::Body::empty())?)
                .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        let devices = body["devices"].as_array().expect("devices array");
        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0]["machine_id"].as_str(),
            Some(this_machine.as_str())
        );
        assert!(devices[0]["is_this_machine"].as_bool().unwrap_or(false));

        // Malformed machine id: 400, nothing enrolled.
        let dir3 = tempfile::tempdir()?;
        let state = owned_state(dir3.path(), [0x52; 32]).await?;
        let app = axum::Router::new()
            .route("/sync/devices/enroll", axum::routing::post(enroll_device))
            .with_state(Arc::clone(&state));
        let (status, body) = response_json(
            app.oneshot(
                axum::http::Request::post("/sync/devices/enroll")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"machine_id":"zz"}"#))?,
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "malformed id: {body:?}");
        Ok(())
    }
}
