//! ADR-0070 §3 (slice 2): API-managed connect/exec ACL entries layered on
//! the operator's TOML floor, with fail-closed hot reload.
//!
//! Model:
//! - The operator TOML file is the **floor**. It is never rewritten; its
//!   entries cannot be removed through the API (`409`).
//! - API-added entries persist in a daemon-owned overlay file per plane
//!   under `<data_dir>/acl/` (`connect-overlay.json`, `exec-overlay.json`).
//! - Effective ACL = floor ∪ overlay, composed by the same validation code
//!   path the TOML parser uses ([`x0x::connect::compose_connect_policy`],
//!   [`x0x::exec::compose_exec_policy`]).
//! - Hot reload (`POST /acl/reload`, `SIGHUP`) re-reads floor and overlay
//!   and swaps the effective policy atomically. Anything malformed, or a
//!   change that needs a restart (plane on/off, exec audit sink), is
//!   rejected: the last validated ACL stays active and the error is
//!   surfaced in `/diagnostics/connect` / `/diagnostics/exec`.
//! - Streams and exec requests already admitted keep the policy they were
//!   checked against (mid-stream revocation is out of scope, ADR-0020).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate as x0x;
use x0x::connect::{ConnectAclEntrySpec, ConnectPolicy};
use x0x::exec::{AclReloadStatus, ExecAclEntrySpec, ExecPolicy, LoadMode};

/// Overlay directory under the daemon data dir.
pub(super) const OVERLAY_DIR: &str = "acl";
const OVERLAY_VERSION: u32 = 1;

/// Failure of an ACL management call, mapped to an HTTP status by the
/// route layer.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum AclAdminError {
    /// The entry fails the TOML parser's validation (`400`).
    BadRequest(String),
    /// Refused by policy: floor entry, disabled plane, no owner (`409`).
    Conflict(String),
    /// No API-managed entry has this id (`404`).
    NotFound(String),
    /// Persistence failed; nothing changed (`500`).
    Internal(String),
}

impl std::fmt::Display for AclAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(m) | Self::Conflict(m) | Self::NotFound(m) | Self::Internal(m) => {
                f.write_str(m)
            }
        }
    }
}

/// One persisted overlay entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlayRecord<S> {
    added_at_unix_ms: u64,
    entry: S,
}

/// On-disk overlay file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlayFile<S> {
    version: u32,
    entries: Vec<OverlayRecord<S>>,
}

/// Per-plane behaviour shared by connect and exec.
trait Plane {
    type Policy: Clone + Send + Sync;
    type Spec: Clone + PartialEq + Serialize + DeserializeOwned + Send + Sync;
    const NAME: &'static str;
    const OVERLAY_FILE: &'static str;

    fn enabled(policy: &Self::Policy) -> bool;
    fn floor_path(policy: &Self::Policy) -> PathBuf;
    fn floor_specs(policy: &Self::Policy) -> Vec<Self::Spec>;
    fn validate(policy: &Self::Policy, spec: &Self::Spec) -> Result<(), String>;
    fn compose(floor: &Self::Policy, overlay: &[Self::Spec]) -> Result<Self::Policy, String>;
    fn reload_compatible(current: &Self::Policy, next: &Self::Policy) -> Result<(), String>;
    fn is_owner_entry(spec: &Self::Spec) -> bool;
    fn summary_json(policy: &Self::Policy) -> serde_json::Value;
    async fn load_floor(path: &Path) -> Result<Self::Policy, String>;
}

struct ConnectPlane;

impl Plane for ConnectPlane {
    type Policy = ConnectPolicy;
    type Spec = ConnectAclEntrySpec;
    const NAME: &'static str = "connect";
    const OVERLAY_FILE: &'static str = "connect-overlay.json";

    fn enabled(policy: &ConnectPolicy) -> bool {
        policy.enabled()
    }
    fn floor_path(policy: &ConnectPolicy) -> PathBuf {
        policy.path().to_path_buf()
    }
    fn floor_specs(policy: &ConnectPolicy) -> Vec<ConnectAclEntrySpec> {
        match policy {
            ConnectPolicy::Enabled(acl) => acl.entry_specs(),
            ConnectPolicy::Disabled { .. } => Vec::new(),
        }
    }
    fn validate(policy: &ConnectPolicy, spec: &ConnectAclEntrySpec) -> Result<(), String> {
        x0x::connect::validate_connect_entry_spec(policy.path(), spec).map_err(|e| e.to_string())
    }
    fn compose(
        floor: &ConnectPolicy,
        overlay: &[ConnectAclEntrySpec],
    ) -> Result<ConnectPolicy, String> {
        x0x::connect::compose_connect_policy(floor, overlay).map_err(|e| e.to_string())
    }
    fn reload_compatible(current: &ConnectPolicy, next: &ConnectPolicy) -> Result<(), String> {
        x0x::connect::connect_reload_compatible(current, next)
    }
    fn is_owner_entry(spec: &ConnectAclEntrySpec) -> bool {
        spec.principal.as_deref() == Some("owner")
    }
    fn summary_json(policy: &ConnectPolicy) -> serde_json::Value {
        serde_json::to_value(policy.summary()).unwrap_or_default()
    }
    async fn load_floor(path: &Path) -> Result<ConnectPolicy, String> {
        // DefaultPath semantics: a vanished file reads as Disabled, which
        // `reload_compatible` then refuses if the plane was enabled.
        x0x::connect::load_connect_policy(Some(path), LoadMode::DefaultPath)
            .await
            .map_err(|e| e.to_string())
    }
}

struct ExecPlane;

impl Plane for ExecPlane {
    type Policy = ExecPolicy;
    type Spec = ExecAclEntrySpec;
    const NAME: &'static str = "exec";
    const OVERLAY_FILE: &'static str = "exec-overlay.json";

    fn enabled(policy: &ExecPolicy) -> bool {
        policy.enabled()
    }
    fn floor_path(policy: &ExecPolicy) -> PathBuf {
        policy.path().to_path_buf()
    }
    fn floor_specs(policy: &ExecPolicy) -> Vec<ExecAclEntrySpec> {
        match policy {
            ExecPolicy::Enabled(acl) => acl.entry_specs(),
            ExecPolicy::Disabled { .. } => Vec::new(),
        }
    }
    fn validate(policy: &ExecPolicy, spec: &ExecAclEntrySpec) -> Result<(), String> {
        x0x::exec::validate_exec_entry_spec(policy.path(), spec).map_err(|e| e.to_string())
    }
    fn compose(floor: &ExecPolicy, overlay: &[ExecAclEntrySpec]) -> Result<ExecPolicy, String> {
        x0x::exec::compose_exec_policy(floor, overlay).map_err(|e| e.to_string())
    }
    fn reload_compatible(current: &ExecPolicy, next: &ExecPolicy) -> Result<(), String> {
        x0x::exec::exec_reload_compatible(current, next)
    }
    fn is_owner_entry(spec: &ExecAclEntrySpec) -> bool {
        spec.principal.as_deref() == Some("owner")
    }
    fn summary_json(policy: &ExecPolicy) -> serde_json::Value {
        serde_json::to_value(policy.summary()).unwrap_or_default()
    }
    async fn load_floor(path: &Path) -> Result<ExecPolicy, String> {
        x0x::exec::load_exec_policy(Some(path), LoadMode::DefaultPath)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Live state of one plane. Mutated only under the plane's mutex, and only
/// after the overlay file write (if any) succeeded.
struct PlaneState<P: Plane> {
    floor: P::Policy,
    overlay: Vec<OverlayRecord<P::Spec>>,
    effective: Arc<P::Policy>,
    status: AclReloadStatus,
    overlay_path: PathBuf,
}

impl<P: Plane> PlaneState<P> {
    fn listing(&self) -> serde_json::Value {
        let floor = P::floor_specs(&self.floor).into_iter().map(|spec| {
            serde_json::json!({
                "id": entry_id("file", &spec),
                "origin": "file",
                "entry": spec,
            })
        });
        let api = self.overlay.iter().map(|r| {
            serde_json::json!({
                "id": entry_id("api", &r.entry),
                "origin": "api",
                "added_at_unix_ms": r.added_at_unix_ms,
                "entry": r.entry,
            })
        });
        serde_json::json!({
            "ok": true,
            "plane": P::NAME,
            "enabled": P::enabled(&self.floor),
            "floor_path": P::floor_path(&self.floor).display().to_string(),
            "overlay_path": self.overlay_path.display().to_string(),
            "entries": floor.chain(api).collect::<Vec<_>>(),
            "summary": P::summary_json(&self.effective),
            "reload": self.status,
        })
    }
}

/// Stable id of an entry: origin prefix + truncated SHA-256 of its
/// canonical JSON. Identical entries share an id, so re-adding is
/// idempotent and a floor entry's id is recognisable on `DELETE`.
fn entry_id<S: Serialize>(origin: &str, spec: &S) -> String {
    let bytes = serde_json::to_vec(spec).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    format!("{origin}-{}", hex::encode(&digest[..8]))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Read one overlay file. Missing ⇒ empty. Malformed, wrong version or a
/// duplicated entry ⇒ error (fail closed; never guess).
async fn read_overlay<P: Plane>(path: &Path) -> Result<Vec<OverlayRecord<P::Spec>>, String> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("failed to read {}: {e}", path.display())),
    };
    let file: OverlayFile<P::Spec> = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    if file.version != OVERLAY_VERSION {
        return Err(format!(
            "{}: unsupported overlay version {} (expected {OVERLAY_VERSION})",
            path.display(),
            file.version
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for record in &file.entries {
        if !seen.insert(entry_id("api", &record.entry)) {
            return Err(format!("{}: duplicate entry", path.display()));
        }
    }
    Ok(file.entries)
}

async fn write_overlay<S: Serialize + Clone>(
    path: &Path,
    entries: &[OverlayRecord<S>],
) -> Result<(), String> {
    let file = OverlayFile {
        version: OVERLAY_VERSION,
        entries: entries.to_vec(),
    };
    let mut bytes = serde_json::to_vec_pretty(&file)
        .map_err(|e| format!("failed to encode {}: {e}", path.display()))?;
    bytes.push(b'\n');
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir).await?;
    }
    // Same helper as the owner key/journal files: temp file in the same
    // directory, fsync, chmod 0600, atomic rename, fsync the directory. An
    // interrupted write leaves only a stray `.<name>.*.tmp`, never a torn
    // overlay.
    x0x::storage::write_private_bytes_durable(path, bytes)
        .await
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

/// Create the overlay directory and restrict it to the daemon user (0700
/// on unix): it holds authorization state, like the key files.
async fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|e| format!("failed to restrict {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Where effective policies are installed once the daemon services exist.
pub(super) struct AclSink {
    pub(super) agent: Arc<x0x::Agent>,
    pub(super) exec_service: Arc<x0x::exec::ExecService>,
    pub(super) connect_diagnostics: Arc<x0x::connect::ConnectDiagnostics>,
}

/// Result of one plane's reload.
#[derive(Debug, Clone, Serialize)]
pub(super) struct PlaneReloadOutcome {
    pub(super) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
    pub(super) status: AclReloadStatus,
}

/// Result of `POST /acl/reload` / `SIGHUP`.
#[derive(Debug, Clone, Serialize)]
pub(super) struct AclReloadReport {
    pub(super) ok: bool,
    pub(super) connect: PlaneReloadOutcome,
    pub(super) exec: PlaneReloadOutcome,
}

/// Owner of both planes' floor, overlay and effective policy.
pub(super) struct AclAdmin {
    connect: tokio::sync::Mutex<PlaneState<ConnectPlane>>,
    exec: tokio::sync::Mutex<PlaneState<ExecPlane>>,
    sink: std::sync::OnceLock<AclSink>,
}

impl AclAdmin {
    /// Load the overlays from `<data_dir>/acl/` and compose them over the
    /// startup floors.
    ///
    /// A malformed or invalid overlay does **not** stop the daemon: overlay
    /// entries only ever add access, so running on the floor alone is
    /// already fail-closed and keeps the daemon available. The bad file is
    /// left untouched on disk, the error is logged and surfaced in
    /// `/diagnostics/{connect,exec}`, and API writes are refused until a
    /// successful reload.
    pub(super) async fn load(
        data_dir: &Path,
        connect_floor: ConnectPolicy,
        exec_floor: ExecPolicy,
    ) -> Self {
        let dir = data_dir.join(OVERLAY_DIR);
        let connect = Self::load_plane::<ConnectPlane>(&dir, connect_floor).await;
        let exec = Self::load_plane::<ExecPlane>(&dir, exec_floor).await;
        Self {
            connect: tokio::sync::Mutex::new(connect),
            exec: tokio::sync::Mutex::new(exec),
            sink: std::sync::OnceLock::new(),
        }
    }

    async fn load_plane<P: Plane>(dir: &Path, floor: P::Policy) -> PlaneState<P> {
        let overlay_path = dir.join(P::OVERLAY_FILE);
        let loaded = match read_overlay::<P>(&overlay_path).await {
            Ok(overlay) => {
                let specs: Vec<P::Spec> = overlay.iter().map(|r| r.entry.clone()).collect();
                P::compose(&floor, &specs)
                    .map(|effective| (overlay, effective))
                    .map_err(|e| format!("{} (from {})", e, overlay_path.display()))
            }
            Err(e) => Err(e),
        };
        match loaded {
            Ok((overlay, effective)) => PlaneState {
                status: AclReloadStatus {
                    api_entry_count: if P::enabled(&floor) { overlay.len() } else { 0 },
                    ..AclReloadStatus::default()
                },
                floor,
                overlay,
                effective: Arc::new(effective),
                overlay_path,
            },
            Err(error) => {
                tracing::error!(
                    plane = P::NAME,
                    %error,
                    "API ACL overlay rejected at startup; running on the TOML floor only, \
                     the file is left untouched and API ACL writes are refused until a \
                     successful reload (ADR-0070)"
                );
                PlaneState {
                    effective: Arc::new(floor.clone()),
                    floor,
                    overlay: Vec::new(),
                    status: AclReloadStatus {
                        overlay_load_failures: 1,
                        overlay_error: Some(error),
                        ..AclReloadStatus::default()
                    },
                    overlay_path,
                }
            }
        }
    }

    /// Effective connect policy (floor ∪ overlay).
    pub(super) async fn effective_connect(&self) -> Arc<ConnectPolicy> {
        Arc::clone(&self.connect.lock().await.effective)
    }

    /// Effective exec policy (floor ∪ overlay).
    pub(super) async fn effective_exec(&self) -> Arc<ExecPolicy> {
        Arc::clone(&self.exec.lock().await.effective)
    }

    /// Install the daemon services that consume effective policies. Called
    /// once at startup, after they were built from the effective policies.
    pub(super) async fn attach(&self, sink: AclSink) {
        if self.sink.set(sink).is_err() {
            tracing::warn!("ACL admin sink attached twice; keeping the first");
            return;
        }
        let connect = self.connect.lock().await;
        let exec = self.exec.lock().await;
        self.publish_connect(&connect);
        self.publish_exec_status(&exec);
    }

    fn publish_connect(&self, state: &PlaneState<ConnectPlane>) {
        if let Some(sink) = self.sink.get() {
            sink.agent.set_connect_policy(Arc::clone(&state.effective));
            sink.connect_diagnostics
                .set_acl_summary(state.effective.summary());
            sink.connect_diagnostics
                .set_acl_reload_status(state.status.clone());
        }
    }

    fn publish_exec_status(&self, state: &PlaneState<ExecPlane>) {
        if let Some(sink) = self.sink.get() {
            sink.exec_service
                .set_acl_reload_status(state.status.clone());
        }
    }

    fn install_exec(&self, effective: &Arc<ExecPolicy>) -> Result<(), String> {
        match self.sink.get() {
            Some(sink) => sink.exec_service.replace_policy(Arc::clone(effective)),
            None => Ok(()),
        }
    }

    /// `GET /acl/connect`.
    pub(super) async fn list_connect(&self) -> serde_json::Value {
        self.connect.lock().await.listing()
    }

    /// `GET /acl/exec`.
    pub(super) async fn list_exec(&self) -> serde_json::Value {
        self.exec.lock().await.listing()
    }

    /// `POST /acl/connect`.
    pub(super) async fn add_connect(
        &self,
        spec: ConnectAclEntrySpec,
        install_has_owner: bool,
    ) -> Result<serde_json::Value, AclAdminError> {
        let mut state = self.connect.lock().await;
        let (value, next) = prepare_add::<ConnectPlane>(&state, spec, install_has_owner)?;
        if let Some((overlay, effective)) = next {
            write_overlay(&state.overlay_path, &overlay)
                .await
                .map_err(AclAdminError::Internal)?;
            commit_edit(&mut state, overlay, effective);
            self.publish_connect(&state);
        }
        Ok(value)
    }

    /// `POST /acl/exec`.
    pub(super) async fn add_exec(
        &self,
        spec: ExecAclEntrySpec,
        install_has_owner: bool,
    ) -> Result<serde_json::Value, AclAdminError> {
        let mut state = self.exec.lock().await;
        let (value, next) = prepare_add::<ExecPlane>(&state, spec, install_has_owner)?;
        if let Some((overlay, effective)) = next {
            write_overlay(&state.overlay_path, &overlay)
                .await
                .map_err(AclAdminError::Internal)?;
            self.install_exec(&effective)
                .map_err(AclAdminError::Internal)?;
            commit_edit(&mut state, overlay, effective);
            self.publish_exec_status(&state);
        }
        Ok(value)
    }

    /// `DELETE /acl/connect/:id`.
    pub(super) async fn remove_connect(
        &self,
        id: &str,
    ) -> Result<serde_json::Value, AclAdminError> {
        let mut state = self.connect.lock().await;
        let (overlay, effective) = prepare_remove::<ConnectPlane>(&state, id)?;
        write_overlay(&state.overlay_path, &overlay)
            .await
            .map_err(AclAdminError::Internal)?;
        commit_edit(&mut state, overlay, effective);
        self.publish_connect(&state);
        Ok(serde_json::json!({ "ok": true, "id": id, "removed": true }))
    }

    /// `DELETE /acl/exec/:id`.
    pub(super) async fn remove_exec(&self, id: &str) -> Result<serde_json::Value, AclAdminError> {
        let mut state = self.exec.lock().await;
        let (overlay, effective) = prepare_remove::<ExecPlane>(&state, id)?;
        write_overlay(&state.overlay_path, &overlay)
            .await
            .map_err(AclAdminError::Internal)?;
        self.install_exec(&effective)
            .map_err(AclAdminError::Internal)?;
        commit_edit(&mut state, overlay, effective);
        self.publish_exec_status(&state);
        Ok(serde_json::json!({ "ok": true, "id": id, "removed": true }))
    }

    /// `POST /acl/reload` / `SIGHUP`: re-read both floors and overlays.
    /// Each plane is reloaded independently; a rejected plane keeps its
    /// last good ACL.
    pub(super) async fn reload(&self) -> AclReloadReport {
        let connect = {
            let mut state = self.connect.lock().await;
            let outcome = match stage_reload::<ConnectPlane>(&state).await {
                Ok(staged) => {
                    commit_reload(&mut state, staged);
                    Ok(())
                }
                Err(e) => Err(note_stage_error(&mut state, e)),
            };
            let outcome = finish_reload(&mut state, outcome);
            self.publish_connect(&state);
            outcome
        };
        let exec = {
            let mut state = self.exec.lock().await;
            let outcome = match stage_reload::<ExecPlane>(&state).await {
                Ok(staged) => match self.install_exec(&staged.2) {
                    Ok(()) => {
                        commit_reload(&mut state, staged);
                        Ok(())
                    }
                    Err(e) => Err(e),
                },
                Err(e) => Err(note_stage_error(&mut state, e)),
            };
            let outcome = finish_reload(&mut state, outcome);
            self.publish_exec_status(&state);
            outcome
        };
        for (plane, outcome) in [("connect", &connect), ("exec", &exec)] {
            match &outcome.error {
                None => tracing::info!(plane, "ACL reload applied (ADR-0070)"),
                Some(error) => tracing::warn!(
                    plane,
                    %error,
                    "ACL reload rejected; last good ACL stays active (ADR-0070)"
                ),
            }
        }
        AclReloadReport {
            ok: connect.ok && exec.ok,
            connect,
            exec,
        }
    }
}

type Staged<P> = (
    <P as Plane>::Policy,
    Vec<OverlayRecord<<P as Plane>::Spec>>,
    Arc<<P as Plane>::Policy>,
);

type NextEdit<P> = (
    Vec<OverlayRecord<<P as Plane>::Spec>>,
    Arc<<P as Plane>::Policy>,
);

/// API writes are refused while the overlay on disk is not in force, so a
/// broken file is never silently overwritten by a rewrite from memory.
fn refuse_while_overlay_broken<P: Plane>(state: &PlaneState<P>) -> Result<(), AclAdminError> {
    match &state.status.overlay_error {
        Some(error) => Err(AclAdminError::Conflict(format!(
            "the {} ACL overlay {} is not in force ({error}); API ACL writes are refused \
             until it is fixed (or moved aside) and `x0x acl reload` succeeds",
            P::NAME,
            state.overlay_path.display()
        ))),
        None => Ok(()),
    }
}

/// Validate an add against the current state. `Ok((body, None))` means the
/// identical entry already exists (idempotent, nothing to write).
fn prepare_add<P: Plane>(
    state: &PlaneState<P>,
    spec: P::Spec,
    install_has_owner: bool,
) -> Result<(serde_json::Value, Option<NextEdit<P>>), AclAdminError> {
    refuse_while_overlay_broken(state)?;
    if P::is_owner_entry(&spec) && !install_has_owner {
        return Err(AclAdminError::Conflict(
            "principal = \"owner\" entries need an owner identity on this install \
             (ADR-0070 §1: installs without an owner have no owner trust)"
                .to_string(),
        ));
    }
    if !P::enabled(&state.floor) {
        return Err(AclAdminError::Conflict(format!(
            "the {} ACL is disabled by its TOML floor ({}); API entries only extend an \
             enabled floor — enable it in the file and restart",
            P::NAME,
            P::floor_path(&state.floor).display()
        )));
    }
    P::validate(&state.floor, &spec).map_err(AclAdminError::BadRequest)?;
    let id = entry_id("api", &spec);
    if state.overlay.iter().any(|r| r.entry == spec) {
        return Ok((
            serde_json::json!({ "ok": true, "id": id, "created": false, "entry": spec }),
            None,
        ));
    }
    let mut overlay = state.overlay.clone();
    overlay.push(OverlayRecord {
        added_at_unix_ms: now_unix_ms(),
        entry: spec.clone(),
    });
    let effective = compose_checked::<P>(state, &overlay).map_err(AclAdminError::BadRequest)?;
    Ok((
        serde_json::json!({ "ok": true, "id": id, "created": true, "entry": spec }),
        Some((overlay, effective)),
    ))
}

fn prepare_remove<P: Plane>(state: &PlaneState<P>, id: &str) -> Result<NextEdit<P>, AclAdminError> {
    refuse_while_overlay_broken(state)?;
    if P::floor_specs(&state.floor)
        .iter()
        .any(|spec| entry_id("file", spec) == id)
    {
        return Err(AclAdminError::Conflict(format!(
            "{id} is an operator TOML floor entry ({}); it cannot be removed via the API — \
             edit the file and reload",
            P::floor_path(&state.floor).display()
        )));
    }
    let Some(pos) = state
        .overlay
        .iter()
        .position(|r| entry_id("api", &r.entry) == id)
    else {
        return Err(AclAdminError::NotFound(format!(
            "no API-managed {} ACL entry with id {id}",
            P::NAME
        )));
    };
    let mut overlay = state.overlay.clone();
    overlay.remove(pos);
    let effective = compose_checked::<P>(state, &overlay).map_err(AclAdminError::Internal)?;
    Ok((overlay, effective))
}

/// Compose floor ∪ `overlay` and confirm it may replace the live policy.
fn compose_checked<P: Plane>(
    state: &PlaneState<P>,
    overlay: &[OverlayRecord<P::Spec>],
) -> Result<Arc<P::Policy>, String> {
    let specs: Vec<P::Spec> = overlay.iter().map(|r| r.entry.clone()).collect();
    let effective = P::compose(&state.floor, &specs)?;
    P::reload_compatible(&state.effective, &effective)?;
    Ok(Arc::new(effective))
}

fn commit_edit<P: Plane>(
    state: &mut PlaneState<P>,
    overlay: Vec<OverlayRecord<P::Spec>>,
    effective: Arc<P::Policy>,
) {
    state.status.api_entry_count = overlay.len();
    state.overlay = overlay;
    state.effective = effective;
}

/// Why a reload was rejected; `overlay_bad` when the overlay file itself
/// (not the floor) is malformed or holds an invalid entry.
struct StageError {
    message: String,
    overlay_bad: bool,
}

/// Read floor + overlay from disk and compose; touches no live state.
async fn stage_reload<P: Plane>(state: &PlaneState<P>) -> Result<Staged<P>, StageError> {
    let floor_err = |message| StageError {
        message,
        overlay_bad: false,
    };
    let overlay_err = |message| StageError {
        message,
        overlay_bad: true,
    };
    let floor = P::load_floor(&P::floor_path(&state.floor))
        .await
        .map_err(floor_err)?;
    let overlay = read_overlay::<P>(&state.overlay_path)
        .await
        .map_err(overlay_err)?;
    let specs: Vec<P::Spec> = overlay.iter().map(|r| r.entry.clone()).collect();
    // The floor parsed on its own, so a composition error is an overlay entry.
    let effective = P::compose(&floor, &specs).map_err(overlay_err)?;
    P::reload_compatible(&state.effective, &effective).map_err(floor_err)?;
    Ok((floor, overlay, Arc::new(effective)))
}

/// Record a rejected reload caused by a bad overlay: keep blocking writes
/// so the broken file on disk is not overwritten.
fn note_stage_error<P: Plane>(state: &mut PlaneState<P>, error: StageError) -> String {
    if error.overlay_bad {
        state.status.overlay_load_failures = state.status.overlay_load_failures.saturating_add(1);
        state.status.overlay_error = Some(error.message.clone());
    }
    error.message
}

fn commit_reload<P: Plane>(state: &mut PlaneState<P>, staged: Staged<P>) {
    let (floor, overlay, effective) = staged;
    state.status.overlay_error = None;
    state.status.api_entry_count = if P::enabled(&floor) { overlay.len() } else { 0 };
    state.floor = floor;
    state.overlay = overlay;
    state.effective = effective;
}

fn finish_reload<P: Plane>(
    state: &mut PlaneState<P>,
    outcome: Result<(), String>,
) -> PlaneReloadOutcome {
    state.status.last_attempt_unix_ms = Some(now_unix_ms());
    let error = match outcome {
        Ok(()) => {
            state.status.reloads_ok = state.status.reloads_ok.saturating_add(1);
            state.status.last_error = None;
            None
        }
        Err(e) => {
            state.status.reloads_failed = state.status.reloads_failed.saturating_add(1);
            state.status.last_error = Some(e.clone());
            Some(e)
        }
    };
    PlaneReloadOutcome {
        ok: error.is_none(),
        error,
        status: state.status.clone(),
    }
}

/// Cloneable handle that lets the daemon binary trigger an ACL reload
/// (e.g. on `SIGHUP`) without reaching into server internals.
#[derive(Clone)]
pub struct AclReloadTrigger(pub(super) Arc<AclAdmin>);

impl AclReloadTrigger {
    /// Re-read both ACL floors and overlays (ADR-0070 §3). A rejected plane
    /// keeps its last good ACL.
    ///
    /// # Errors
    /// Names every plane whose reload was rejected.
    pub async fn reload(&self) -> anyhow::Result<()> {
        let report = self.0.reload().await;
        if report.ok {
            return Ok(());
        }
        let errors: Vec<String> = [("connect", &report.connect), ("exec", &report.exec)]
            .iter()
            .filter_map(|(plane, o)| o.error.as_ref().map(|e| format!("{plane}: {e}")))
            .collect();
        Err(anyhow::anyhow!(
            "ACL reload rejected (last good ACL kept): {}",
            errors.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests;
