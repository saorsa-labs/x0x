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

use std::sync::{Arc, Weak};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde::Serialize;

use super::status::ApiResponse;
use crate::owner_sync::{
    local_names_of, OwnerEnrollment, OwnerSyncService, PersistedNames, SyncDaemonView,
    SyncProfileNames, SyncValue, VersionedRecord,
};
use crate::profile::SelfProfile;
use crate::server::state::AppState;

/// Adapter over live daemon state for the sync service.
///
/// `profile_names` keeps a last-seen mirror: `apply_names` writes it
/// synchronously so the very next reconcile pass cannot re-mint a
/// pre-merge value (LWW flip-back), while the live `AppState` profile and
/// its persisted file catch up in a spawned task. `names_settled` waits
/// for those tasks; a task that saves the profile discharges the synced
/// names it holds, and the reconcile pass keeps a name owed until a save
/// discharges it (#1545).
///
/// WHY a `Weak<AppState>`: the view is installed on the sync service the
/// `AppState` owns (`state.owner_sync`), so an `Arc` here is a cycle
/// (`AppState` -> `OwnerSyncService` -> view -> `AppState`) that nothing
/// breaks: a stopped owner install's state, and every task and handle it
/// holds, would never be freed (W3-H S3: the restart drain guard). The
/// same reason as the task-list gates in `routes/tasks.rs`. While the
/// daemon runs its router and tasks hold the state, so every upgrade
/// succeeds; an expired `Weak` means the daemon is gone, and the view then
/// answers as it does when unsure (mirror names, no pointer, fail closed).
pub(in crate::server) struct DaemonView {
    state: Weak<AppState>,
    names: std::sync::RwLock<SyncProfileNames>,
    /// One receiver per catch-up task that may still run; each closes
    /// when its task ends (or is refused at shutdown).
    pending: std::sync::Mutex<Vec<tokio::sync::watch::Receiver<()>>>,
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
            state: Arc::downgrade(&state),
            names: std::sync::RwLock::new(names),
            pending: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Install a view over `state` on `service`, as the daemon does.
    ///
    /// #1545: first remove the pending applies that the loaded profile
    /// already holds (`OwnerSyncStore::settle_saved`), so that no pass
    /// applies them over a local edit saved before the start. The loaded
    /// profile is made durable first: a save that stopped after its
    /// rename and before its directory fsync is visible but not durable,
    /// and a host crash after the settle would bring back the old profile
    /// with nothing owed. When it cannot be made durable, nothing settles.
    pub(in crate::server) async fn attach(service: &OwnerSyncService, state: &Arc<AppState>) {
        {
            // The read lock keeps every save out until the settle is done.
            let profile = state.profile.read().await;
            if let Err(e) = crate::profile::make_durable(&state.profile_path).await {
                tracing::warn!(target: "x0x::owner_sync", error = %e, "cannot make the loaded profile durable; saved names not settled");
            } else if let Err(e) = service.store().settle_saved(&names_of(&profile)).await {
                tracing::warn!(target: "x0x::owner_sync", error = %e, "failed to settle saved names");
            }
        }
        service.attach_daemon_view(Arc::new(Self::new(Arc::clone(state))));
    }
}

impl SyncDaemonView for DaemonView {
    fn profile_names(&self) -> SyncProfileNames {
        if let Some(state) = self.state.upgrade() {
            if let Ok(profile) = state.profile.try_read() {
                let fresh = names_of(&profile);
                *self
                    .names
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh.clone();
                return fresh;
            }
        }
        // Lock contended (or the daemon gone): report the last-seen mirror
        // (never a regression to empty — a mint from a wrong default would
        // fight the winner).
        self.names
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn home_pointer(&self) -> Option<SyncValue> {
        // Best-effort (try_read): the reconcile pass tolerates a missed
        // snapshot; the SESSION PATH must not — it uses
        // `home_pointer_definitive` (#863 r2 review finding 2).
        let state = self.state.upgrade()?;
        let owner = state.agent.identity().user_keypair()?.user_id();
        let local_hex = hex::encode(state.agent.agent_id().as_bytes());
        let groups = state.named_groups.try_read().ok()?;
        home_pointer_from_state(&state, &owner, &local_hex, &groups)
    }

    fn home_pointer_definitive(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<SyncValue>, ()>> + Send>>
    {
        // #863 r2 (review finding 2): the AWAITED read — lock contention
        // waits and is never mistaken for "no Home" (tokio's RwLock does
        // not poison). `Err(())` survives only for the no-owner-key
        // case; the session path treats Err as fail-closed. A daemon that
        // is gone cannot read its Home definitively either: fail closed.
        let state = self.state.upgrade();
        Box::pin(async move {
            let Some(state) = state else {
                return Err(());
            };
            let owner = match state.agent.identity().user_keypair() {
                Some(kp) => kp.user_id(),
                // Anonymous install: nothing to understate.
                None => return Ok(None),
            };
            let local_hex = hex::encode(state.agent.agent_id().as_bytes());
            let groups = state.named_groups.read().await;
            Ok(home_pointer_from_state(&state, &owner, &local_hex, &groups))
        })
    }

    fn canonical_pointer_is_retired(&self, group_id: &str) -> bool {
        // Fail SAFE when the roster lock is contended: "unsure" must answer
        // false, so a busy daemon never mints over a live canonical Home.
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        let Ok(groups) = state.named_groups.try_read() else {
            return false;
        };
        groups.iter().any(|(id, info)| {
            (id.as_str() == group_id || info.stable_group_id() == group_id) && info.withdrawn
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
        // A daemon that is gone has no live profile to catch up.
        let Some(state) = self.state.upgrade() else {
            return;
        };
        // #1274: the catch-up persists the profile, so it runs shielded
        // (`AppState::spawn_shielded`): the shutdown drain waits for a write
        // in progress instead of leaving it to outlive the daemon with this
        // AppState (and `history.db`) held, and refuses one that has not
        // started, as if the sync had arrived after the stop.
        let (done, done_rx) = tokio::sync::watch::channel(());
        {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // `has_changed` is `Err` once a task has ended.
            pending.retain(|task| task.has_changed().is_ok());
            pending.push(done_rx);
        }
        let task_state = Arc::clone(&state);
        state.spawn_shielded(async move {
            // `done` drops when the task ends, which completes
            // `names_settled`.
            let _done = done;
            let state = task_state;
            let mut profile = state.profile.write().await;
            // #1545: apply the names still owed, not the values of this
            // call. A local edit (`PUT /profile`) that ran after this call
            // already folded them in and discharged them; applying the
            // values of this call again would put them over that edit.
            let owed = fold_owed_names(&state, &mut profile).await;
            let changed = match &owed {
                Some((changed, _)) => *changed,
                None => set_names(
                    &mut profile,
                    SyncProfileNames {
                        human_name,
                        display_name,
                        machine_name,
                    },
                ),
            };
            // The announce self-name follows the merged display name
            // (mirrors PUT /profile).
            if changed {
                state.agent.set_self_name(profile.display_name.clone());
            }
            // Save even when the live profile already holds the names: an
            // earlier save of them can have failed. Save under the profile
            // lock, so a later local edit cannot save first and then be
            // overwritten by this save (#1545).
            // A failed save leaves the names owed in the store, and the
            // next pass applies them again.
            if let Err(e) = save_profile(&state, &profile, owed.map(|(_, folded)| folded)).await {
                tracing::warn!(
                    target: "x0x::owner_sync",
                    "failed to persist synced profile: {e}"
                );
            }
        });
    }
}

/// Set each name of `names` that is `Some` on `profile`. Returns whether
/// anything changed.
fn set_names(profile: &mut SelfProfile, names: SyncProfileNames) -> bool {
    let mut changed = false;
    for (slot, name) in [
        (&mut profile.human_name, names.human_name),
        (&mut profile.display_name, names.display_name),
        (&mut profile.machine_name, names.machine_name),
    ] {
        if name.is_some() && *slot != name {
            *slot = name;
            changed = true;
        }
    }
    changed
}

/// #1545: put the synced names that are still owed to this machine into
/// `profile`, which the caller holds under the profile write lock. Every
/// writer of the profile calls this before its own change and then saves,
/// so a local edit always comes after the synced names committed before
/// it. Returns whether `profile` changed and the records read, each with
/// whether it was applied (it was the register's winner); the caller
/// saves them with `save_profile`. `None` when the daemon has no owner
/// sync.
pub(in crate::server) async fn fold_owed_names(
    state: &AppState,
    profile: &mut SelfProfile,
) -> Option<(bool, Vec<(VersionedRecord, bool)>)> {
    let sync = state.owner_sync.as_ref()?;
    let local = state.agent.machine_id();
    let mut changed = false;
    let mut folded = Vec::new();
    for (record, winner) in sync.store().pending_applies().await {
        // A record that is not the register's winner is not applied: a
        // later commit replaced it, or its own commit did not complete.
        // The discharge retires it only if it is still not the winner.
        if winner {
            if let Some(names) = local_names_of(&record, &local) {
                changed |= set_names(profile, names);
            }
        }
        folded.push((record, winner));
    }
    Some((changed, folded))
}

/// The sync names of `profile`.
fn names_of(profile: &SelfProfile) -> SyncProfileNames {
    SyncProfileNames {
        human_name: profile.human_name.clone(),
        display_name: profile.display_name.clone(),
        machine_name: profile.machine_name.clone(),
    }
}

/// #1545: durably save `profile`, which the caller holds under the profile
/// write lock, with the records `folded` of `fold_owed_names` in it. The
/// store first notes the save (`OwnerSyncStore::note_profile_save`), and
/// after the save it discharges `folded`. Thus a discharge that does not
/// reach the disk cannot bring the records back over this save, or over a
/// local edit in it.
///
/// # Errors
///
/// The IO error of the note or of the save. The profile is not saved when
/// the note fails, or after shutdown, and `folded` stays owed.
pub(in crate::server) async fn save_profile(
    state: &AppState,
    profile: &SelfProfile,
    folded: Option<Vec<(VersionedRecord, bool)>>,
) -> std::io::Result<()> {
    let owed = state.owner_sync.as_ref().zip(folded.as_deref());
    if let Some((sync, folded)) = owed {
        sync.store()
            .note_profile_save(folded, &names_of(profile))
            .await
            .map_err(|e| std::io::Error::other(format!("note the profile save: {e}")))?;
    }
    match state.owner_sync.as_ref() {
        // #1545: the save holds the store's write custody until it lands,
        // as the store's own writes do, so shutdown waits for it and a
        // save after shutdown is refused.
        Some(sync) => {
            let (profile, path) = (profile.clone(), state.profile_path.clone());
            sync.store()
                .run_to_completion(async move {
                    profile
                        .save_to(&path)
                        .await
                        .map_err(|e| crate::owner_sync::SyncError::Io(e.to_string()))
                })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        None => profile.save_to(&state.profile_path).await?,
    }
    if let Some((sync, folded)) = owed {
        if let Err(e) = sync.store().discharge_applies(folded).await {
            tracing::warn!(target: "x0x::owner_sync", error = %e, "failed to discharge applied names");
        }
    }
    Ok(())
}

impl PersistedNames for DaemonView {
    fn names_settled(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Box::pin(async move {
            for mut task in pending {
                // `changed` fails once the task drops its sender, at its
                // end.
                while task.changed().await.is_ok() {}
            }
        })
    }

    fn live_names(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SyncProfileNames> + Send>> {
        let state = self.state.upgrade();
        let mirror = self
            .names
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Box::pin(async move {
            // A daemon that is gone has no live profile; its mirror is the
            // last one seen, as in `profile_names`.
            match state {
                Some(state) => names_of(&*state.profile.read().await),
                None => mirror,
            }
        })
    }
}

/// The Home-pointer computation over a HELD `named_groups` guard —
/// shared by the best-effort and the definitive reads (#863 r2).
fn home_pointer_from_state(
    state: &AppState,
    owner: &crate::identity::UserId,
    local_hex: &str,
    groups: &std::collections::HashMap<String, crate::groups::GroupInfo>,
) -> Option<SyncValue> {
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
        let pending = state
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
                && super::home::is_home_policy(&info.policy, owner)
                && info.has_active_member(local_hex)
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
        // #1055 RC2: a tombstoned enrollment is a REFUSAL the caller can
        // correct (re-enroll with a later enrolled_at), not a storage
        // failure — 409, not 500.
        if matches!(e, crate::owner_sync::SyncError::EnrollmentTombstoned { .. }) {
            return error_response(
                StatusCode::CONFLICT,
                "enrollment_tombstoned: the machine was unenrolled; a re-enroll needs a freshly issued enrollment with a later enrolled_at",
            );
        }
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
/// machine is refused, and a live session from it stops at its next
/// admission re-check (phase or page boundary, or before its commit —
/// #1055). The DELETE also writes a durable unenroll tombstone — including
/// on the not-enrolled (`404`) path — that refuses any later enroll,
/// restore or replay at or before the delete time.
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

    /// #863 r2 (review finding 1, Rule 9): the SESSION PATH publishes the
    /// local Home pointer before the version-vector exchange. Two services
    /// over a duplex pipe: the responder holds an UNPUBLISHED Home; running
    /// the responder side through `session_with_home_publication` (the
    /// composition both production session directions call), the initiator
    /// must RECEIVE the HomePointer record. Reverting the session-path
    /// composition (the materialization removed) leaves the initiator's
    /// store without it (the fail-before).
    /// #1097: a pre-rename publication failure must fail both sessions and
    /// leave the rank-0 peer waiting; clearing the fault permits publication.
    #[tokio::test]
    async fn session_path_publishes_home_pointer_before_the_exchange() {
        use crate::server::routes::home::tests::owned_state;
        let dir_a = tempfile::tempdir().expect("dir a");
        let dir_b = tempfile::tempdir().expect("dir b");
        let a = owned_state(dir_a.path(), [0x8E; 32])
            .await
            .expect("state a");
        let b = owned_state(dir_b.path(), [0x8E; 32])
            .await
            .expect("state b");
        // The pointerless initiator must be rank 0: a falsely successful
        // empty session would release its Home provisioning wait.
        let (dir_a, _dir_b, a, b) = if a.agent.machine_id().0 > b.agent.machine_id().0 {
            (dir_a, dir_b, a, b)
        } else {
            (dir_b, dir_a, b, a)
        };
        // Views attached exactly as the server startup does.
        for state in [&a, &b] {
            DaemonView::attach(
                state.owner_sync.as_ref().expect("owned state wires sync"),
                state,
            )
            .await;
        }
        let sync_a = a.owner_sync.as_ref().expect("sync a");
        let sync_b = b.owner_sync.as_ref().expect("sync b");
        let owner_kp = a
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");
        let machine_a = a.agent.machine_id();
        let machine_b = b.agent.machine_id();
        // Mutual enrollment.
        sync_a
            .store()
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(machine_b, owner_kp, 1_000, None)
                    .expect("enroll b"),
            )
            .await
            .expect("persist enroll b");
        sync_b
            .store()
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(machine_a, owner_kp, 1_000, None)
                    .expect("enroll a"),
            )
            .await
            .expect("persist enroll a");

        // The RESPONDER holds an UNPUBLISHED Home.
        crate::server::routes::home::provision_home(&a).await;
        assert!(sync_a.canonical_home().await.is_none(), "unpublished");

        let waiting = crate::server::routes::home::tests::wait_for_rank_zero_owner_sync_round(
            &b,
            std::time::Duration::from_secs(3_600),
        );
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        let sessions_a = sync_a.store().successful_sessions_rx();
        let sessions_b = sync_b.store().successful_sessions_rx();
        let before_a = *sessions_a.borrow();
        let before_b = *sessions_b.borrow();

        // Inject an I/O failure BEFORE rename, without losing enrollment:
        // a file in place of the sync directory prevents temp-file creation.
        let sync_dir = dir_a.path().join("sync");
        let saved_sync_dir = dir_a.path().join("sync-saved");
        std::fs::rename(&sync_dir, &saved_sync_dir).expect("save sync directory");
        std::fs::write(&sync_dir, b"not a directory").expect("block persistence");
        let (client, server) = tokio::io::duplex(64 * 1024);
        let responder = async {
            let (mut recv, mut send) = tokio::io::split(server);
            sync_a
                .session_with_home_publication(
                    &mut send, &mut recv, owner_kp, &machine_a, &machine_b,
                )
                .await
            // Drop both halves on return, as the production caller does,
            // so the peer observes EOF when publication fails.
        };
        let initiator = async {
            let (mut recv, mut send) = tokio::io::split(client);
            sync_b
                .session_with_home_publication(
                    &mut send, &mut recv, owner_kp, &machine_b, &machine_a,
                )
                .await
        };
        let (responder_out, initiator_out) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(responder, initiator)
            })
            .await
            .expect("both session ends must terminate");
        // Mirror handle_inbound / dial_and_sync's outcome accounting.
        sync_a
            .store()
            .set_session_status(&machine_b, responder_out.is_ok())
            .await;
        sync_b
            .store()
            .set_session_status(&machine_a, initiator_out.is_ok())
            .await;
        assert!(
            matches!(&responder_out, Err(crate::owner_sync::SyncError::Io(_))),
            "pre-rename publication failure must fail the responder: {responder_out:?}"
        );
        assert!(
            initiator_out.is_err(),
            "peer session must fail: {initiator_out:?}"
        );
        for (sync, peer) in [(sync_a, machine_b), (sync_b, machine_a)] {
            assert!(!sync.store().session_statuses().await[&peer.0].last_session_ok);
            assert!(
                sync.canonical_home().await.is_none(),
                "mint rolled back / no pointer received"
            );
            assert!(
                sync.store().poisoned_reason().is_none(),
                "pre-rename failure does not poison"
            );
        }
        assert_eq!(*sessions_a.borrow(), before_a, "no responder success");
        assert_eq!(*sessions_b.borrow(), before_b, "no initiator success");
        assert!(
            futures_util::poll!(waiting.as_mut()).is_pending(),
            "failed publication must not release the rank-0 Home wait"
        );
        std::fs::remove_file(&sync_dir).expect("clear persistence fault");
        std::fs::rename(&saved_sync_dir, &sync_dir).expect("restore sync directory");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let (mut b_recv, mut b_send) = tokio::io::split(server);
        let (mut a_recv, mut a_send) = tokio::io::split(client);
        let responder = sync_a.session_with_home_publication(
            &mut b_send,
            &mut b_recv,
            owner_kp,
            &machine_a,
            &machine_b,
        );
        let initiator = sync_b.session_with_home_publication(
            &mut a_send,
            &mut a_recv,
            owner_kp,
            &machine_b,
            &machine_a,
        );
        let (responder_out, initiator_out) = tokio::join!(responder, initiator);
        assert!(
            responder_out.is_ok(),
            "responder session: {responder_out:?}"
        );
        assert!(
            initiator_out.is_ok(),
            "initiator session: {initiator_out:?}"
        );
        // THE assertion: the initiator received the HomePointer record —
        // only possible because the responder's session path published its
        // pointer BEFORE the version-vector exchange.
        let canonical = sync_b.canonical_home().await.expect("HomePointer received");
        let (gid, _) = crate::server::routes::home::find_home(&a, &owner_kp.user_id())
            .await
            .expect("a's Home");
        assert_eq!(canonical.group_id, gid);
        assert!(
            futures_util::poll!(waiting.as_mut()).is_ready(),
            "successful pointer publication releases the rank-0 Home wait"
        );
    }

    /// Codex review of #1545 (6bec48c), P2: `DaemonView::apply_names`
    /// updates the live profile in a spawned task. A reconcile pass that
    /// recovers the profile `Alice` must wait for that task, or its
    /// `profile_names` reads the old live name and mints `Old` over
    /// `Alice` at a higher version. The single-thread runtime does not
    /// run the spawned task before the pass reads, unless the pass waits.
    #[tokio::test]
    async fn a_recovered_profile_is_not_republished_as_the_old_live_name() {
        use crate::owner_sync::SyncKind;
        let dir = tempfile::tempdir().expect("tmpdir");
        let state = owned_state(dir.path(), [0x87; 32]).await.expect("state");
        state.profile.write().await.human_name = Some("Old".into());
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        let owner = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");

        // A remote device's journal renewal and profile `Alice` (version 2),
        // committed as one batch whose journal append fails after the
        // journal intent is durable.
        let batch = remote_alice_batch(dir.path(), owner).await;
        let store = service.store();
        store.set_fail_journal_append(true);
        let failed = store.commit_batch(batch, &owner.user_id()).await;
        assert!(failed.is_err(), "a failed journal append fails the commit");
        store.set_fail_journal_append(false);

        service.sync_all().await;
        assert_eq!(
            store.stored_value(SyncKind::OwnerProfile, "owner").await,
            Some(SyncValue::OwnerProfile {
                human_name: Some("Alice".into())
            }),
            "the reconcile must not publish the old live name"
        );
        assert_eq!(
            state.profile.read().await.human_name.as_deref(),
            Some("Alice"),
            "the daemon must show the recovered profile"
        );
    }

    /// A remote device's signed journal renewal and owner profile `Alice`
    /// (version 2), for the recovery tests.
    async fn remote_alice_batch(
        dir: &std::path::Path,
        owner: &crate::identity::UserKeypair,
    ) -> Vec<crate::owner_sync::VersionedRecord> {
        use crate::owner_sync::{OwnerSyncStore, SyncKind};
        let remote = OwnerSyncStore::load(&dir.join("remote"))
            .await
            .expect("remote store");
        let remote_machine = crate::identity::MachineId([2; 32]);
        remote
            .mint(
                SyncKind::IssuanceJournal,
                "bb",
                &SyncValue::IssuanceJournal {
                    agent_id: "bb".to_string(),
                    cert_digest: "d2".to_string(),
                    issued_at: 100,
                    not_after: Some(9_000),
                },
                owner,
                remote_machine,
            )
            .await
            .expect("remote journal mint");
        for name in ["first", "Alice"] {
            remote
                .mint(
                    SyncKind::OwnerProfile,
                    "owner",
                    &SyncValue::OwnerProfile {
                        human_name: Some(name.into()),
                    },
                    owner,
                    remote_machine,
                )
                .await
                .expect("remote profile mint");
        }
        remote.records_snapshot().await
    }

    /// Codex review of #1545 (f2688b2), P2: a recovery commits the profile
    /// `Alice` and removes its journal intent, and the process stops before
    /// the live profile catch-up saves `Alice`. The restart loads the old
    /// profile from disk. The reconcile must apply `Alice` again, not mint
    /// the old name over it at a higher version.
    #[tokio::test]
    async fn a_restart_before_the_profile_catch_up_keeps_the_recovered_profile() {
        use crate::owner_sync::SyncKind;
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x88; 32];
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        {
            let state = owned_state(dir.path(), seed).await.expect("state");
            {
                let mut profile = state.profile.write().await;
                profile.human_name = Some("Old".into());
                profile
                    .save_to(&state.profile_path)
                    .await
                    .expect("save the old profile");
            }
            let service = state.owner_sync.as_ref().expect("owned state wires sync");
            DaemonView::attach(service, &state).await;
            service.sync_all().await;

            let batch = remote_alice_batch(dir.path(), &owner).await;
            let store = service.store();
            store.set_fail_journal_append(true);
            let failed = store.commit_batch(batch, &owner.user_id()).await;
            assert!(failed.is_err(), "a failed journal append fails the commit");
            store.set_fail_journal_append(false);
            // The reconcile's recovery step, and then the process stops
            // before any record reaches the live profile.
            store
                .recover_interrupted_commit(&owner.user_id())
                .await
                .expect("recovery");
        }

        let state = owned_state(dir.path(), seed)
            .await
            .expect("restarted state");
        assert_eq!(
            state.profile.read().await.human_name.as_deref(),
            Some("Old"),
            "the restart loads the old profile"
        );
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        assert_eq!(
            service
                .store()
                .stored_value(SyncKind::OwnerProfile, "owner")
                .await,
            Some(SyncValue::OwnerProfile {
                human_name: Some("Alice".into())
            }),
            "the reconcile must not publish the old profile over the recovered one"
        );
        assert_eq!(
            state.profile.read().await.human_name.as_deref(),
            Some("Alice"),
            "the daemon must show the recovered profile after the restart"
        );
    }

    /// Codex review of #1545 (29e2800), P2: a session commits and applies
    /// the profile `Alice`, and its obligation stays until a pass discharges
    /// it. A local `PUT /profile` then saves `Bob`. The next reconcile must
    /// publish `Bob`, not apply `Alice` again over the newer local edit.
    #[tokio::test]
    async fn a_local_edit_after_a_synced_apply_is_not_overwritten() {
        use crate::owner_sync::SyncKind;
        let dir = tempfile::tempdir().expect("tmpdir");
        let state = owned_state(dir.path(), [0x89; 32]).await.expect("state");
        state.profile.write().await.human_name = Some("Old".into());
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        let view = Arc::new(DaemonView::new(Arc::clone(&state)));
        service.attach_daemon_view(Arc::clone(&view));
        service.sync_all().await;
        let owner = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");

        // The session: commit, then apply the accepted records.
        let batch = remote_alice_batch(dir.path(), owner).await;
        let outcome = service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("commit");
        for record in &outcome.accepted {
            service.apply_record(record);
        }
        view.names_settled().await;
        assert_eq!(
            state.profile.read().await.human_name.as_deref(),
            Some("Alice")
        );

        let (status, _) = super::super::profile::update_profile(
            State(Arc::clone(&state)),
            Json(super::super::profile::UpdateProfileRequest {
                human_name: Some("Bob".into()),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        service.sync_all().await;
        assert_eq!(
            state.profile.read().await.human_name.as_deref(),
            Some("Bob"),
            "the daemon must keep the local edit"
        );
        assert_eq!(
            service
                .store()
                .stored_value(SyncKind::OwnerProfile, "owner")
                .await,
            Some(SyncValue::OwnerProfile {
                human_name: Some("Bob".into())
            }),
            "the reconcile must publish the local edit"
        );
    }

    /// A daemon with the saved profile `Old` and an owed, committed
    /// profile `Alice` that no pass applied yet.
    async fn state_owing_alice(dir: &std::path::Path, seed: [u8; 32]) -> Arc<AppState> {
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        let state = owned_state(dir, seed).await.expect("state");
        {
            let mut profile = state.profile.write().await;
            profile.human_name = Some("Old".into());
            profile
                .save_to(&state.profile_path)
                .await
                .expect("save the old profile");
        }
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        let batch = remote_alice_batch(dir, &owner).await;
        service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("commit");
        state
    }

    /// `PUT /profile` with the human name `name`.
    async fn put_name(state: &Arc<AppState>, name: &str) -> StatusCode {
        let (status, _) = super::super::profile::update_profile(
            State(Arc::clone(state)),
            Json(super::super::profile::UpdateProfileRequest {
                human_name: Some(name.into()),
                ..Default::default()
            }),
        )
        .await;
        status
    }

    /// The daemon shows and publishes the profile `name`.
    async fn assert_keeps(state: &AppState, name: &str, why: &str) {
        use crate::owner_sync::SyncKind;
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        assert_eq!(
            state.profile.read().await.human_name.as_deref(),
            Some(name),
            "{why}: the daemon must keep the profile"
        );
        assert_eq!(
            service
                .store()
                .stored_value(SyncKind::OwnerProfile, "owner")
                .await,
            Some(SyncValue::OwnerProfile {
                human_name: Some(name.into())
            }),
            "{why}: the reconcile must publish the profile"
        );
    }

    /// Codex review of #1545 (f16c484), P2: `PUT /profile` folds the owed
    /// `Alice` in, saves `Bob` and clears the obligation. The host then
    /// crashes. The clear must be durable, or the restart applies `Alice`
    /// again over the durable `Bob`.
    #[tokio::test]
    async fn a_crash_after_a_local_edit_keeps_the_edit() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x8A; 32];
        let (pending_path, profile_path) = {
            let state = state_owing_alice(dir.path(), seed).await;
            assert_eq!(put_name(&state, "Bob").await, StatusCode::OK);
            let service = state.owner_sync.as_ref().expect("owned state wires sync");
            (
                service.store().pending_applies_path(),
                state.profile_path.clone(),
            )
        };
        // The host crashes before any pass: every write that was not
        // made durable is lost.
        crate::profile::crash_sim::crash(&[&pending_path, &profile_path]);

        let state = owned_state(dir.path(), seed)
            .await
            .expect("restarted state");
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        assert_keeps(&state, "Bob", "after the crash").await;
    }

    /// Codex review of #1545 (f16c484), P2: `PUT /profile` folds the owed
    /// `Alice` in and saves `Bob`, and then the clear of the obligation
    /// fails. The edit is saved, so the PUT succeeds. The next pass, and a
    /// restart, must keep `Bob` and not apply `Alice` again.
    #[tokio::test]
    async fn a_failed_discharge_after_a_local_edit_keeps_the_edit() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x8B; 32];
        {
            let state = state_owing_alice(dir.path(), seed).await;
            let service = state.owner_sync.as_ref().expect("owned state wires sync");
            service.store().fail_next_discharge();
            assert_eq!(put_name(&state, "Bob").await, StatusCode::OK);
            service.sync_all().await;
            assert_keeps(&state, "Bob", "after the failed discharge").await;
        }

        let state = owned_state(dir.path(), seed)
            .await
            .expect("restarted state");
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        assert_keeps(&state, "Bob", "after a restart").await;
    }

    /// Codex review of #1545 (0f55c78), P2: with `Alice` owed, `PUT
    /// /profile` saves `Bob` and its discharge fails; a second `PUT
    /// /profile` then saves `Carol`. A restart before any pass must keep
    /// `Carol`, not apply `Alice` again over it.
    #[tokio::test]
    async fn a_second_local_edit_after_a_failed_discharge_keeps_the_edit() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x8E; 32];
        {
            let state = state_owing_alice(dir.path(), seed).await;
            let service = state.owner_sync.as_ref().expect("owned state wires sync");
            service.store().fail_next_discharge();
            assert_eq!(put_name(&state, "Bob").await, StatusCode::OK);
            assert_eq!(put_name(&state, "Carol").await, StatusCode::OK);
        }

        let state = owned_state(dir.path(), seed)
            .await
            .expect("restarted state");
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        assert_keeps(&state, "Carol", "after a restart").await;
    }

    /// Codex review of #1545 (17e0dae3), P2: with `Alice` owed, `PUT
    /// /profile` saves `Bob`, and the process stops after the rename and
    /// before the directory fsync: `Bob` is visible, not durable, and
    /// `Alice` stays owed. The restart loads `Bob` and settles `Alice`
    /// durably. A host crash then brings back `Old`. The restart after it
    /// must not publish `Old` over the synced name.
    #[tokio::test]
    async fn a_crash_after_a_restart_that_settled_a_visible_save_keeps_the_save() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x8F; 32];
        let (pending_path, profile_path) = {
            let state = state_owing_alice(dir.path(), seed).await;
            let service = state.owner_sync.as_ref().expect("owned state wires sync");
            let old = std::fs::read(&state.profile_path).expect("old profile");
            service.store().fail_next_discharge();
            assert_eq!(put_name(&state, "Bob").await, StatusCode::OK);
            // Model the stop: only `Old` is durable, `Bob` is visible.
            let bob = std::fs::read(&state.profile_path).expect("bob profile");
            std::fs::write(&state.profile_path, &old).expect("write old");
            crate::profile::crash_sim::note_durable(&state.profile_path);
            std::fs::write(&state.profile_path, &bob).expect("write bob");
            (
                service.store().pending_applies_path(),
                state.profile_path.clone(),
            )
        };
        {
            let state = owned_state(dir.path(), seed)
                .await
                .expect("restarted state");
            let service = state.owner_sync.as_ref().expect("owned state wires sync");
            DaemonView::attach(service, &state).await;
        }
        crate::profile::crash_sim::crash(&[&pending_path, &profile_path]);

        let state = owned_state(dir.path(), seed)
            .await
            .expect("restarted state");
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        assert_keeps(&state, "Bob", "after the second restart").await;
    }

    /// Codex review of #1545 (0f55c78), P2: the reconcile reads the live
    /// name `Old` and finds no owed names; a session then commits `Alice`
    /// before the reconcile mints. The mint must not put `Old` over
    /// `Alice` at a higher version, or the catch-up skips `Alice` as no
    /// longer the winner and the synced name is lost.
    #[tokio::test]
    async fn a_commit_during_the_reconcile_name_mint_keeps_the_synced_name() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let state = owned_state(dir.path(), [0x8F; 32]).await.expect("state");
        state.profile.write().await.human_name = Some("Old".into());
        let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));
        let view = Arc::new(DaemonView::new(Arc::clone(&state)));
        service.attach_daemon_view(Arc::clone(&view));
        service.sync_all().await;
        let owner = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");

        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        service.store().pause_next_name_mint(read_tx, release_rx);
        let pass = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.sync_all().await }
        });
        read_rx.await.expect("the reconcile reads the live names");

        // The session commits `Alice` while the reconcile holds `Old`.
        let batch = remote_alice_batch(dir.path(), owner).await;
        let outcome = service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("commit");
        release_tx.send(()).expect("release the reconcile");
        pass.await.expect("the pass ends");
        // The session applies what it committed.
        for record in &outcome.accepted {
            service.apply_record(record);
        }
        view.names_settled().await;

        service.sync_all().await;
        assert_keeps(&state, "Alice", "after the interleaved commit").await;
    }

    /// The owner profile register holds `name`.
    async fn assert_register_holds(state: &AppState, name: &str, why: &str) {
        use crate::owner_sync::SyncKind;
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        assert_eq!(
            service
                .store()
                .stored_value(SyncKind::OwnerProfile, "owner")
                .await,
            Some(SyncValue::OwnerProfile {
                human_name: Some(name.into())
            }),
            "{why}"
        );
    }

    /// Codex review of #1545 (a139ad9), P2: the reconcile reads the live
    /// name `Old`; a session then commits `Alice`, and the catch-up saves
    /// `Alice` and discharges it, all before the reconcile mints. Nothing
    /// is owed any more at the mint, but the names the reconcile read are
    /// older than that discharge. The mint must not put `Old` over `Alice`
    /// at a higher version.
    #[tokio::test]
    async fn a_discharge_during_the_reconcile_name_mint_keeps_the_synced_name() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let state = owned_state(dir.path(), [0x90; 32]).await.expect("state");
        state.profile.write().await.human_name = Some("Old".into());
        let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));
        let view = Arc::new(DaemonView::new(Arc::clone(&state)));
        service.attach_daemon_view(Arc::clone(&view));
        service.sync_all().await;
        let owner = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");

        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        service.store().pause_next_name_mint(read_tx, release_rx);
        let pass = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.sync_all().await }
        });
        read_rx.await.expect("the reconcile reads the live names");

        // The session commits and applies `Alice`, and the catch-up saves
        // and discharges it, while the reconcile holds `Old`.
        let batch = remote_alice_batch(dir.path(), owner).await;
        let outcome = service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("commit");
        for record in &outcome.accepted {
            service.apply_record(record);
        }
        view.names_settled().await;
        release_tx.send(()).expect("release the reconcile");
        pass.await.expect("the pass ends");
        assert_register_holds(
            &state,
            "Alice",
            "the reconcile must not publish the names it read before the discharge",
        )
        .await;

        service.sync_all().await;
        assert_keeps(&state, "Alice", "after the interleaved discharge").await;
    }

    /// Codex review of #1545 (e3089a4), P2: the catch-up of `Alice` fails
    /// to save the profile. `PUT /profile` then saves `Bob` and discharges
    /// `Alice`. A remote machine's names arrive next; they set no local
    /// name, so no catch-up runs for them. The failed save of `Alice` is
    /// for an obligation that the save of `Bob` retired, so it must not
    /// keep the reconcile from publishing `Bob`.
    #[tokio::test]
    async fn a_failed_catch_up_then_a_local_edit_keeps_the_names_published() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x93; 32];
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        let state = owned_state(dir.path(), seed).await.expect("state");
        {
            let mut profile = state.profile.write().await;
            profile.human_name = Some("Old".into());
            profile
                .save_to(&state.profile_path)
                .await
                .expect("save the old profile");
        }
        let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));
        DaemonView::attach(&service, &state).await;
        service.sync_all().await;
        assert_register_holds(&state, "Old", "the first pass publishes Old").await;

        // A directory in place of the profile file fails every save.
        tokio::fs::remove_file(&state.profile_path)
            .await
            .expect("remove the profile");
        tokio::fs::create_dir(&state.profile_path)
            .await
            .expect("block the profile save");
        let batch = remote_alice_profile(dir.path(), &owner).await;
        service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("commit Alice");
        service.sync_all().await;
        assert!(
            !service.store().pending_applies().await.is_empty(),
            "the failed catch-up keeps Alice owed"
        );

        tokio::fs::remove_dir(&state.profile_path)
            .await
            .expect("unblock the profile save");
        assert_eq!(put_name(&state, "Bob").await, StatusCode::OK);
        assert!(
            service.store().pending_applies().await.is_empty(),
            "the save of Bob discharges Alice"
        );

        // Another machine's names arrive; they set no local name.
        let remote = crate::owner_sync::OwnerSyncStore::load(&dir.path().join("remote-names"))
            .await
            .expect("remote store");
        let remote_machine = crate::identity::MachineId([3; 32]);
        remote
            .mint(
                crate::owner_sync::SyncKind::MachineNames,
                &hex::encode(remote_machine.0),
                &SyncValue::MachineNames {
                    display_name: Some("remote-agent".into()),
                    machine_name: Some("remote-mac".into()),
                },
                &owner,
                remote_machine,
            )
            .await
            .expect("remote names mint");
        service
            .store()
            .commit_batch(remote.records_snapshot().await, &owner.user_id())
            .await
            .expect("commit the remote names");

        service.sync_all().await;
        assert_keeps(&state, "Bob", "after a failed catch-up and a local edit").await;
        assert!(
            service.store().pending_applies().await.is_empty(),
            "the remote names are discharged"
        );
    }

    /// A remote device's owner profile `Alice` (version 2) only.
    async fn remote_alice_profile(
        dir: &std::path::Path,
        owner: &crate::identity::UserKeypair,
    ) -> Vec<crate::owner_sync::VersionedRecord> {
        let mut batch = remote_alice_batch(dir, owner).await;
        batch.retain(|r| r.kind == crate::owner_sync::SyncKind::OwnerProfile);
        batch
    }

    /// A daemon with the saved and published profile `Old`, and a commit
    /// of the remote profile `Alice` whose register write failed after
    /// its pending apply was durable. Returns the batch to retry.
    async fn state_after_a_failed_alice_commit(
        dir: &std::path::Path,
        seed: [u8; 32],
    ) -> (Arc<AppState>, Vec<crate::owner_sync::VersionedRecord>) {
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        let state = owned_state(dir, seed).await.expect("state");
        {
            let mut profile = state.profile.write().await;
            profile.human_name = Some("Old".into());
            profile
                .save_to(&state.profile_path)
                .await
                .expect("save the old profile");
        }
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        assert_register_holds(&state, "Old", "the first pass publishes Old").await;
        let batch = remote_alice_profile(dir, &owner).await;
        service.store().fail_next_register_write();
        let failed = service
            .store()
            .commit_batch(batch.clone(), &owner.user_id())
            .await;
        assert!(failed.is_err(), "a failed register write fails the commit");
        (state, batch)
    }

    /// Codex review of #1545 (a139ad9), P2: a commit of `Alice` fails at
    /// its register write, so its pending apply is not the register's
    /// winner. The reconcile reads the pending applies and finds nothing
    /// to apply. Before it discharges them, a session retries the commit
    /// and `Alice` becomes the winner. The discharge must keep `Alice`
    /// owed, or the reconcile publishes `Old` over it and no catch-up
    /// applies it.
    #[tokio::test]
    async fn a_retried_commit_during_the_reconcile_discharge_stays_owed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x91; 32];
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        let (state, batch) = state_after_a_failed_alice_commit(dir.path(), seed).await;
        let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));

        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        service.store().pause_next_discharge(reached_tx, release_rx);
        let pass = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.sync_all().await }
        });
        reached_rx
            .await
            .expect("the reconcile reaches its discharge");

        let outcome = service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("the retried commit");
        assert_eq!(outcome.accepted.len(), 1, "the retry commits Alice");
        release_tx.send(()).expect("release the reconcile");
        pass.await.expect("the pass ends");
        assert_register_holds(
            &state,
            "Alice",
            "the reconcile must not publish Old over the retried commit",
        )
        .await;

        // The session applies what it committed.
        for record in &outcome.accepted {
            service.apply_record(record);
        }
        service.sync_all().await;
        assert_keeps(&state, "Alice", "after the retried commit").await;
    }

    /// The same as `a_retried_commit_during_the_reconcile_discharge_stays_owed`,
    /// with the discharge of a local edit: `PUT /profile` folds the
    /// non-winning `Alice` without an apply and saves `Bob`; the retried
    /// commit makes `Alice` the winner before the PUT discharges it. Then
    /// `stop` either lets the PUT finish (`false`) or stops the daemon
    /// before the discharge (`true`). In both cases `Alice` is the newest
    /// committed name and must stay owed: neither the discharge nor the
    /// start-up settle of the saved `Bob` may retire it.
    async fn retried_commit_during_a_local_edit_discharge(seed: [u8; 32], stop: bool) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        let (state, batch) = state_after_a_failed_alice_commit(dir.path(), seed).await;
        let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));

        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        service.store().pause_next_discharge(reached_tx, release_rx);
        let put = tokio::spawn({
            let state = Arc::clone(&state);
            async move { put_name(&state, "Bob").await }
        });
        reached_rx.await.expect("the PUT reaches its discharge");

        let outcome = service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("the retried commit");
        assert_eq!(outcome.accepted.len(), 1, "the retry commits Alice");

        if stop {
            // The daemon stops after the PUT saved `Bob` and before its
            // discharge, and before the session applies `Alice`.
            put.abort();
            assert!(put.await.is_err(), "the PUT stops at its discharge");
            drop(release_tx);
            drop(service);
            drop(state);
            let state = owned_state(dir.path(), seed)
                .await
                .expect("restarted state");
            let service = state.owner_sync.as_ref().expect("owned state wires sync");
            DaemonView::attach(service, &state).await;
            service.sync_all().await;
            assert_keeps(&state, "Alice", "after a stop before the discharge").await;
            return;
        }

        release_tx.send(()).expect("release the PUT");
        assert_eq!(put.await.expect("the PUT ends"), StatusCode::OK);
        for record in &outcome.accepted {
            service.apply_record(record);
        }
        service.sync_all().await;
        assert_keeps(&state, "Alice", "after the retried commit").await;
    }

    /// See `retried_commit_during_a_local_edit_discharge`.
    #[tokio::test]
    async fn a_retried_commit_during_a_local_edit_discharge_stays_owed() {
        retried_commit_during_a_local_edit_discharge([0x92; 32], false).await;
    }

    /// See `retried_commit_during_a_local_edit_discharge`.
    #[tokio::test]
    async fn a_stop_after_a_local_edit_keeps_a_retried_commit_owed() {
        retried_commit_during_a_local_edit_discharge([0x93; 32], true).await;
    }

    /// A commit of `Alice` fails at its register write. `PUT /profile`
    /// saves `Bob` and discharges the non-winning `Alice`, but the write
    /// of the discharge fails, so `Alice` stays in memory as discharged.
    /// A retried commit then makes `Alice` the winner. The commit must
    /// make `Alice` owed again, not leave it discharged.
    #[tokio::test]
    async fn a_retried_commit_after_a_failed_discharge_stays_owed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x94; 32];
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        let (state, batch) = state_after_a_failed_alice_commit(dir.path(), seed).await;
        let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));
        service.store().fail_next_discharge();
        assert_eq!(put_name(&state, "Bob").await, StatusCode::OK);

        let outcome = service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("the retried commit");
        assert_eq!(outcome.accepted.len(), 1, "the retry commits Alice");
        for record in &outcome.accepted {
            service.apply_record(record);
        }
        service.sync_all().await;
        assert_keeps(&state, "Alice", "after the retried commit").await;
    }

    /// A session commits `Alice`, and `PUT /profile` folds it in, saves
    /// `Bob` and discharges it before the session applies `Alice`, so the
    /// view's name mirror still shows `Old`. The reconcile then reads the
    /// names while a profile writer holds the lock. It must not mint the
    /// stale mirror `Old`; it reads the live profile `Bob`.
    #[tokio::test]
    async fn a_contended_profile_read_does_not_publish_stale_names() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let state = owned_state(dir.path(), [0x95; 32]).await.expect("state");
        state.profile.write().await.human_name = Some("Old".into());
        let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));
        let view = Arc::new(DaemonView::new(Arc::clone(&state)));
        service.attach_daemon_view(Arc::clone(&view));
        service.sync_all().await;
        let owner = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");
        let batch = remote_alice_profile(dir.path(), owner).await;
        service
            .store()
            .commit_batch(batch, &owner.user_id())
            .await
            .expect("commit");
        assert_eq!(put_name(&state, "Bob").await, StatusCode::OK);

        let writer = state.profile.write().await;
        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        service.store().pause_next_name_mint(read_tx, release_rx);
        let pass = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.sync_all().await }
        });
        // A reconcile that reads the mirror gets here while the writer
        // holds the lock; one that waits for the lock gets here after.
        let mut read_rx = read_rx;
        let early = tokio::time::timeout(std::time::Duration::from_secs(2), &mut read_rx).await;
        drop(writer);
        if early.is_err() {
            read_rx.await.expect("the reconcile reads the live names");
        }
        release_tx.send(()).expect("release the reconcile");
        pass.await.expect("the pass ends");
        assert_register_holds(
            &state,
            "Bob",
            "the reconcile must publish the live profile, not the stale mirror",
        )
        .await;
    }

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

    /// Codex review of #1545 (b17cd8bf), round 7: `Alice` is owed.
    /// `PUT Bob` is cancelled (the client goes away) during the rename of
    /// its profile save, and `PUT Carol` then completes. The late rename of
    /// Bob's save must not put Bob on disk over the durable Carol: a
    /// restart would show Bob, and Carol's discharge of Alice would stand
    /// on a save that the disk does not hold.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_put_cancelled_during_its_save_cannot_land_over_a_later_put() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let state = state_owing_alice(dir.path(), [0x8E; 32]).await;
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        crate::profile::journal_faults::pause_next_rename(
            &state.profile_path,
            reached_tx,
            release_rx,
        );
        let bob = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { put_name(&state, "Bob").await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), reached_rx)
            .await
            .expect("Bob's save reaches its rename")
            .expect("rename hook");
        bob.abort();
        let _ = bob.await;

        let mut carol = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { put_name(&state, "Carol").await })
        };
        let early = tokio::time::timeout(std::time::Duration::from_secs(1), &mut carol).await;
        release_tx.send(()).expect("release Bob's rename");
        let status = match early {
            Ok(done) => done.expect("PUT Carol"),
            Err(_) => carol.await.expect("PUT Carol"),
        };
        assert_eq!(status, StatusCode::OK);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let durable = crate::profile::SelfProfile::load_from(&state.profile_path)
            .await
            .expect("read the profile")
            .expect("a saved profile");
        assert_eq!(
            durable.human_name.as_deref(),
            Some("Carol"),
            "the late save of a cancelled PUT must not land over a later PUT"
        );
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        service.sync_all().await;
        assert_keeps(&state, "Carol", "after a cancelled PUT").await;
        drop(state);

        let state = owned_state(dir.path(), [0x8E; 32])
            .await
            .expect("restarted state");
        let service = state.owner_sync.as_ref().expect("owned state wires sync");
        DaemonView::attach(service, &state).await;
        service.sync_all().await;
        assert_keeps(&state, "Carol", "after a restart").await;
    }

    /// Codex review of #1545 (3a28bef1): a mint of the register is held at
    /// its rename, and shutdown aborts its caller. The shutdown drain must
    /// wait for the write before the daemon gives up the data directory: a
    /// daemon restarted on the same directory must not see the late rename
    /// of the old write land over its own newer register.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_drains_a_held_write_before_a_restart_can_write() {
        use crate::identity::MachineId;
        use crate::owner_sync::{SyncKind, SyncValue};
        let seed = [0x8F; 32];
        let owner = Arc::new(crate::identity::UserKeypair::from_seed(&seed).expect("owner key"));
        let profile = |human: &str| SyncValue::OwnerProfile {
            human_name: Some(human.into()),
        };
        let dir = tempfile::tempdir().expect("tmpdir");
        let state = owned_state(dir.path(), seed).await.expect("state");
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        crate::profile::journal_faults::pause_next_rename(
            &dir.path().join("sync").join("records.json"),
            reached_tx,
            release_rx,
        );
        let old = {
            let service = Arc::clone(state.owner_sync.as_ref().expect("owned state wires sync"));
            let (owner, desired) = (Arc::clone(&owner), profile("Old"));
            tokio::spawn(async move {
                let _ = service
                    .store()
                    .mint(
                        SyncKind::OwnerProfile,
                        "owner",
                        &desired,
                        &owner,
                        MachineId([1; 32]),
                    )
                    .await;
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), reached_rx)
            .await
            .expect("the old write reaches its rename")
            .expect("rename hook");

        // Shutdown aborts the caller (as the drain does to a periodic pass
        // past its grace); the held write ends one second from now,
        // whatever the drain does.
        old.abort();
        let _ = old.await;
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let _ = release_tx.send(());
        });
        crate::server::drain_server_tasks(&state, Vec::new()).await;
        drop(state);

        let state = owned_state(dir.path(), seed)
            .await
            .expect("restarted state");
        let store = Arc::clone(state.owner_sync.as_ref().expect("sync").store());
        store
            .mint(
                SyncKind::OwnerProfile,
                "owner",
                &profile("New"),
                &owner,
                MachineId([1; 32]),
            )
            .await
            .expect("mint after the restart");
        releaser.join().expect("releaser");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let disk = crate::owner_sync::OwnerSyncStore::load(dir.path())
            .await
            .expect("reload");
        assert_eq!(
            disk.stored_value(SyncKind::OwnerProfile, "owner").await,
            Some(profile("New")),
            "a write of the old daemon must not land after its shutdown"
        );
    }

    /// Codex review of #1545 (1e46704b), P2: a commit of a synced issuance
    /// line is held at the rename of its journal write, and shutdown aborts
    /// its caller. The shutdown drain must wait for the journal write
    /// before the daemon gives up the data directory: else a replacement
    /// process can write a newer journal that the late rename replaces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_drains_a_held_journal_write() {
        use crate::identity::MachineId;
        use crate::owner_sync::{OwnerSyncStore, SyncKind, SyncValue};
        let seed = [0x90; 32];
        let owner = crate::identity::UserKeypair::from_seed(&seed).expect("owner key");
        let dir = tempfile::tempdir().expect("tmpdir");
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let agent_hex = hex::encode([0x42; 32]);
        remote
            .mint(
                SyncKind::IssuanceJournal,
                &agent_hex,
                &SyncValue::IssuanceJournal {
                    agent_id: agent_hex.clone(),
                    cert_digest: "held".into(),
                    issued_at: 100,
                    not_after: None,
                },
                &owner,
                MachineId([2; 32]),
            )
            .await
            .expect("remote mint");
        let synced = remote.records_snapshot().await;

        let state = owned_state(&dir.path().join("local"), seed)
            .await
            .expect("state");
        let journal = state
            .agent
            .cert_journal_path()
            .expect("journal path")
            .to_path_buf();
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        crate::profile::journal_faults::pause_next_rename(&journal, reached_tx, release_rx);
        let commit = {
            let store = Arc::clone(state.owner_sync.as_ref().expect("sync").store());
            let owner = owner.user_id();
            tokio::spawn(async move {
                let _ = store.commit_batch(synced, &owner).await;
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), reached_rx)
            .await
            .expect("the journal write reaches its rename")
            .expect("rename hook");

        // Shutdown aborts the caller; the held rename ends one second from
        // now, whatever the drain does.
        commit.abort();
        let _ = commit.await;
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let _ = release_tx.send(());
        });
        crate::server::drain_server_tasks(&state, Vec::new()).await;
        let landed = crate::profile::IssuedCertRecord::load(&journal)
            .await
            .iter()
            .any(|line| line.cert_digest == "held");
        releaser.join().expect("releaser");
        assert!(
            landed,
            "shutdown must wait for a journal write before it gives up the data directory"
        );
    }

    /// WHY (#1055 RC2, review of RC1): a tombstoned enroll is a REFUSAL the
    /// caller can correct, not a storage failure — the route must answer
    /// `409 enrollment_tombstoned`, never `500 failed to persist`. The
    /// tombstone is seeded far in the machine's future (enroll with a
    /// far-future `enrolled_at_ms`, then DELETE it) so ANY enrollment the
    /// route can sign now predates it — deterministic, no clock race.
    #[tokio::test]
    async fn enroll_refuses_a_tombstoned_machine_with_409() -> anyhow::Result<()> {
        use crate::server::rider_auth::ActorContext;
        use tower::ServiceExt;
        const OWNER: ActorContext = ActorContext::Owner { durable: true };

        let dir = tempfile::tempdir()?;
        let state = owned_state(dir.path(), [0x53; 32]).await?;
        let app = axum::Router::new()
            .route("/sync/devices/enroll", axum::routing::post(enroll_device))
            .with_state(Arc::clone(&state));
        let sync = state.owner_sync.as_ref().expect("owned state wires sync");
        let owner_kp = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");
        // A peer machine, deleted after a far-future enrollment: the RC1
        // tombstone floor (max with the deleted enrollment's OWN timestamp)
        // puts the tombstone far beyond `now`.
        let peer = crate::identity::MachineId([0x53; 32]);
        sync.store()
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(peer, owner_kp, u64::MAX / 2, None)
                    .expect("sign far-future enrollment"),
            )
            .await
            .expect("seed enrollment");
        assert!(
            sync.store().unenroll(&peer).await.expect("delete"),
            "seeding the tombstone"
        );

        let (status, body) = response_json(
            app.oneshot(
                axum::http::Request::post("/sync/devices/enroll")
                    .header("content-type", "application/json")
                    .extension(OWNER)
                    .body(axum::body::Body::from(
                        serde_json::json!({ "machine_id": hex::encode(peer.0) }).to_string(),
                    ))?,
            )
            .await?,
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a tombstoned enroll is a refusal (409), not a storage failure: {body:?}"
        );
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("enrollment_tombstoned")),
            "the refusal must name its cause: {body:?}"
        );
        Ok(())
    }
}
