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
        let local_hex = hex::encode(self.state.agent.agent_id().as_bytes());
        let groups = self.state.named_groups.try_read().ok()?;
        // #449 (D4): this MUST use the same predicate as
        // `routes::home::find_home` — a weaker one (any owner-certified
        // group carrying Home metadata) let a device publish a Home it is
        // not a member of, or a half-shaped group, as the owner's Home.
        // Combined with `.find()` over an UNORDERED map that made the
        // published pointer nondeterministic: with two Home-stamped groups
        // in the roster (exactly what cross-device adoption creates) the
        // selection could differ on every reconcile pass, and every flip
        // re-minted the `"home"` record. Select the lexicographically
        // smallest stable id so the choice is stable across passes.
        let pending: Vec<String> = {
            let pending = self
                .state
                .pending_join_stubs
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.iter().cloned().collect()
        };
        groups
            .iter()
            .filter(|(id, info)| {
                !pending.iter().any(|p| p == id.as_str())
                    // Review P2: withdrawal keeps `home` and `members_v2`
                    // populated, so without this a RETIRED Home would be
                    // republished as the owner's canonical one — and because
                    // provisioning yields to a named canonical Home, every
                    // device would then refuse to make a replacement while
                    // `GET /home` reported `elsewhere`. Mirrors the
                    // `!withdrawn` guard in `find_home`.
                    && !info.withdrawn
                    && info.home.is_some()
                    && super::home::is_home_policy(&info.policy, &owner)
                    && info.has_active_member(&local_hex)
            })
            .map(|(_, info)| info)
            .min_by(|a, b| a.stable_group_id().cmp(b.stable_group_id()))
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
    expires_at_ms: Option<u64>,
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
                expires_at_ms: enrollment.expires_at_ms,
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
/// omitted = enroll THIS machine. `ttl_secs` optional bounds the
/// enrollment's lifetime (review R2 finding 1); omitted = until deleted.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct EnrollRequest {
    machine_id: Option<String>,
    ttl_secs: Option<u64>,
}

/// POST /sync/devices/enroll response body.
#[derive(Debug, Serialize)]
pub(in crate::server) struct EnrollData {
    machine_id: String,
    enrolled_at_ms: u64,
    expires_at_ms: Option<u64>,
    device_count: usize,
}

/// POST /sync/devices/enroll — owner-key-sign a `DeviceEnrollment` for a
/// machine and add it to the local owner device set (owner-gated: the
/// daemon must hold the owner key; ADR-0043 enrollment direction).
///
/// The signature and the enrollment's currency (expiry) are verified again
/// at every stream accept, so a corrupt, foreign-key, or stale enrollment
/// can never open the sync gate. A persistence failure is a 500 — success
/// is never reported on a swallowed write (review R2 finding 2).
pub(in crate::server) async fn enroll_device(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<EnrollRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Issue #446: enrolling a machine widens the Tier-1 owner device
    // set — the enrollment is owner-key signed, but a 10-minute session
    // bearer must not be able to widen (or, below, shrink) the device
    // set. Checked FIRST so the 403 does not depend on sync being
    // configured.
    if !actor.is_durable_owner() {
        return error_response(
            StatusCode::FORBIDDEN,
            "device enrollment requires the durable API token (not a session token)",
        );
    }
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
    let expires_at_ms = req
        .ttl_secs
        .map(|ttl| enrolled_at_ms.saturating_add(ttl.saturating_mul(1000)));
    let enrollment = match OwnerEnrollment::sign(machine, owner_kp, enrolled_at_ms, expires_at_ms) {
        Ok(enrollment) => enrollment,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let machine_hex = hex::encode(enrollment.machine_id);
    if let Err(e) = sync.store().enroll(enrollment).await {
        // Never report success on a swallowed write (review R2 finding 2).
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to persist enrollment: {e}"),
        );
    }
    let device_count = sync.store().enrolled_devices().await.len();
    // Enrollment is Tier-1-relevant state: kick an early sync pass.
    sync.kick();
    let body = ApiResponse {
        ok: true,
        data: EnrollData {
            machine_id: machine_hex,
            enrolled_at_ms,
            expires_at_ms,
            device_count,
        },
    };
    (
        StatusCode::OK,
        Json(serde_json::to_value(body).unwrap_or_default()),
    )
}

/// DELETE /sync/devices/:machine_id response body.
#[derive(Debug, Serialize)]
pub(in crate::server) struct UnenrollData {
    machine_id: String,
    device_count: usize,
}

/// DELETE /sync/devices/:machine_id — remove a machine from the owner
/// device set (owner-gated). The very next inbound SyncV1 stream from that
/// machine is refused at the enrollment gate; existing streams are not
/// torn down mid-flight (per-accept gating, ADR-0022 posture).
pub(in crate::server) async fn unenroll_device(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    axum::extract::Path(machine_hex): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Issue #446: removing a real device is an availability act on the
    // owner device set — durable token required, symmetric with enroll.
    if !actor.is_durable_owner() {
        return error_response(
            StatusCode::FORBIDDEN,
            "device removal requires the durable API token (not a session token)",
        );
    }
    let Some(sync) = state.owner_sync.as_ref() else {
        return error_response(StatusCode::CONFLICT, "no owner identity configured");
    };
    let Some(machine) = decode_machine_id(&machine_hex) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "machine_id must be 64 hex characters",
        );
    };
    match sync.store().unenroll(&machine).await {
        Ok(true) => {
            let device_count = sync.store().enrolled_devices().await.len();
            sync.kick();
            let body = ApiResponse {
                ok: true,
                data: UnenrollData {
                    machine_id: machine_hex,
                    device_count,
                },
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(body).unwrap_or_default()),
            )
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, "machine not enrolled"),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to persist device set: {e}"),
        ),
    }
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

    /// Build a Home-shaped group for `owner`, optionally seating `member`.
    fn home_group(
        state: &AppState,
        owner: &crate::identity::UserId,
        group_id: &str,
        seat_local_agent: bool,
    ) -> crate::groups::GroupInfo {
        let mut info = crate::groups::GroupInfo::with_policy(
            "Home".to_string(),
            String::new(),
            state.agent.agent_id(),
            group_id.to_string(),
            crate::server::routes::home::home_policy(owner),
        );
        info.home = Some(crate::groups::HomeMetadata {
            primary_agent: hex::encode(state.agent.agent_id().as_bytes()),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 0,
        });
        if !seat_local_agent {
            info.members_v2.clear();
        }
        info
    }

    /// WHY (#449 D4): the pointer this device publishes as "the owner's
    /// Home" must be the SAME group `find_home` would resolve, and must not
    /// change between reconcile passes.
    ///
    /// The old predicate accepted any owner-certified group carrying Home
    /// metadata — no full policy match, no membership check — and selected
    /// it with `.find()` over an unordered map. With two Home-stamped groups
    /// in the roster (exactly what cross-device adoption creates) the choice
    /// could differ every pass, and each flip re-minted the `"home"` record.
    /// Two independently-seeded roster maps (distinct `RandomState`, so
    /// distinct iteration orders) holding the SAME two Home-shaped groups
    /// must publish the SAME pointer — a property `.find()` cannot give.
    #[tokio::test]
    async fn published_home_pointer_is_stable_across_passes() -> anyhow::Result<()> {
        // The duplicate-Home situation #449 is about: two Home-shaped groups
        // for one owner, inserted in opposite orders on two daemons.
        let (lo, hi) = ("aa".repeat(16), "bb".repeat(16));
        let mut published = Vec::new();
        let dirs = [tempfile::tempdir()?, tempfile::tempdir()?];

        for (i, dir) in dirs.iter().enumerate() {
            let state = owned_state(dir.path(), [0x4A; 32]).await?;
            let owner = state
                .agent
                .identity()
                .user_keypair()
                .expect("owned state has a user key")
                .user_id();
            {
                let mut groups = state.named_groups.write().await;
                let order = if i == 0 { [&hi, &lo] } else { [&lo, &hi] };
                for id in order {
                    groups.insert(id.clone(), home_group(&state, &owner, id, true));
                }
            }
            let view = DaemonView::new(Arc::clone(&state));
            let SyncValue::HomePointer { group_id, .. } =
                view.home_pointer().expect("a Home is published")
            else {
                panic!("home_pointer must publish a HomePointer");
            };
            published.push(group_id);
        }

        assert_eq!(
            published[0], published[1],
            "two daemons with the same two Homes must publish the same pointer"
        );
        assert_eq!(
            published[0], lo,
            "selection is the smallest stable group id, never map iteration order"
        );
        Ok(())
    }

    /// WHY (review P2): a RETIRED Home must never be advertised as canonical.
    ///
    /// Withdrawal keeps `home` and `members_v2` populated, so without an
    /// explicit guard the publisher would republish a retired Home as the
    /// owner's canonical one. Because provisioning yields to a named canonical
    /// Home, every device would then refuse to create a replacement while
    /// `GET /home` reported `elsewhere` — the owner would be left with no Home
    /// and no way to get one. Mirrors the `!withdrawn` guard in `find_home`.
    #[tokio::test]
    async fn a_withdrawn_home_is_never_published_as_canonical() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4C; 32]).await?;
        let owner = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key")
            .user_id();

        let id = "dd".repeat(16);
        let mut info = home_group(&state, &owner, &id, true);
        assert!(
            info.has_active_member(&hex::encode(state.agent.agent_id().as_bytes())),
            "precondition: seated, so only `withdrawn` can exclude it"
        );
        info.withdrawn = true;
        state.named_groups.write().await.insert(id, info);

        let view = DaemonView::new(Arc::clone(&state));
        assert!(
            view.home_pointer().is_none(),
            "a withdrawn Home must not be advertised as the owner's canonical Home"
        );
        Ok(())
    }

    /// WHY (#449 D4): a Home we are not seated in belongs to another device.
    /// Publishing it as ours would advertise a Home we cannot serve and, once
    /// the apply arm acts on pointers, would let a non-member overwrite the
    /// owner's canonical Home.
    #[tokio::test]
    async fn home_pointer_ignores_a_home_we_are_not_a_member_of() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x4B; 32]).await?;
        let owner = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key")
            .user_id();

        let foreign = "cc".repeat(16);
        state
            .named_groups
            .write()
            .await
            .insert(foreign.clone(), home_group(&state, &owner, &foreign, false));

        let view = DaemonView::new(Arc::clone(&state));
        assert!(
            view.home_pointer().is_none(),
            "a Home without our agent seated must not be published as ours"
        );
        Ok(())
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
        use crate::server::rider_auth::ActorContext;
        use tower::ServiceExt;
        const OWNER: ActorContext = ActorContext::Owner { durable: true };

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
                        .extension(OWNER)
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
            .route(
                "/sync/devices/:machine_id",
                axum::routing::delete(unenroll_device),
            )
            .with_state(Arc::clone(&state));
        let (status, body) = response_json(
            app.clone()
                .oneshot(
                    axum::http::Request::post("/sync/devices/enroll")
                        .header("content-type", "application/json")
                        .extension(OWNER)
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
            app.clone()
                .oneshot(axum::http::Request::get("/sync/devices").body(axum::body::Body::empty())?)
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
        // Enroll with a TTL, then revoke it via the DELETE path: the list
        // empties and a second revoke 404s (review R2 finding 1).
        let (status, body) = response_json(
            app.clone()
                .oneshot(
                    axum::http::Request::post("/sync/devices/enroll")
                        .header("content-type", "application/json")
                        .extension(OWNER)
                        .body(axum::body::Body::from(r#"{"ttl_secs":3600}"#))?,
                )
                .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "enroll with ttl: {body:?}");
        assert!(
            body["expires_at_ms"].as_u64().is_some(),
            "ttl produced an expiry"
        );
        let (status, body) = response_json(
            app.clone()
                .oneshot(
                    axum::http::Request::delete(format!("/sync/devices/{this_machine}"))
                        .extension(OWNER)
                        .body(axum::body::Body::empty())?,
                )
                .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "revoke: {body:?}");
        let (status, body) = response_json(
            app.clone()
                .oneshot(axum::http::Request::get("/sync/devices").body(axum::body::Body::empty())?)
                .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["devices"].as_array().map(Vec::len),
            Some(0),
            "revoked machine gone from the device set"
        );
        let (status, body) = response_json(
            app.oneshot(
                axum::http::Request::delete(format!("/sync/devices/{this_machine}"))
                    .extension(OWNER)
                    .body(axum::body::Body::empty())?,
            )
            .await?,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "second revoke 404s: {body:?}"
        );

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
                    .extension(OWNER)
                    .body(axum::body::Body::from(r#"{"machine_id":"zz"}"#))?,
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "malformed id: {body:?}");
        Ok(())
    }
}
