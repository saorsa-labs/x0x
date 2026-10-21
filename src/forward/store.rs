//! Persistent forwards (ADR-0074 §2): `<data_dir>/forwards.json`.
//!
//! Forwards persist by default; `--ephemeral` opts out (Q3). Each record
//! pins the agent the forward opens streams to and the machine every stream
//! must reach, plus the loopback target. On restart the daemon re-resolves
//! a named record through the name store (where the name's pin applies)
//! and brings the forward up only when the name still denotes exactly the
//! pinned ids; otherwise the forward stays down with a reported reason and
//! is never silently retargeted.
//!
//! The file is versioned JSON with `deny_unknown_fields`, written with
//! [`crate::storage::write_private_bytes_durable_typed_after_rename`] (temp
//! file, fsync, mode `0600`, atomic rename) — the same pattern as
//! `names.json`. A missing file is an empty store; an unreadable or
//! malformed one leaves the store refusing persistent operations, and it is
//! never overwritten. A failure before the rename leaves memory unchanged.
//! A failure after the rename keeps the new set in memory so it matches
//! the file, and reports [`ForwardStoreError::Unconfirmed`] until a later
//! write confirms the parent-directory fsync.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::ForwardSpec;
use crate::identity::{AgentId, MachineId};
use crate::names::{NameError, NameKind, NameRef, Resolved};

/// File name of the forward store inside the daemon data dir.
pub const FORWARDS_STORE_FILE: &str = "forwards.json";

/// Upper bound on persisted forwards (a larger file is refused).
pub const MAX_FORWARDS: usize = 1024;

/// Reason code for a restored forward whose name now resolves to other ids
/// (ADR-0074 §2 `name_changed`, known_hosts semantics).
pub const NAME_CHANGED: &str = "name_changed";

const STORE_VERSION: u32 = 1;

/// Why the forward store refused an operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForwardStoreError {
    /// The on-disk file could not be read or parsed (fail closed).
    #[error("forward store not usable: {0}")]
    Unusable(String),
    /// Persisting failed before the rename. Memory and disk are unchanged.
    #[error("forward store write failed: {0}")]
    Write(String),
    /// The new bytes are in place and memory matches them, but the
    /// parent-directory fsync did not confirm durability. Callers must not
    /// roll the change back. A later mutation retries the write.
    #[error(
        "applied, but durability is not confirmed (directory fsync failed): {0}; the change is in \
         effect"
    )]
    Unconfirmed(String),
    /// The store already holds [`MAX_FORWARDS`] records.
    #[error("forward store is full ({MAX_FORWARDS} forwards)")]
    Full,
    /// A persistent forward must carry a pinned machine (ADR-0074 §1).
    #[error(
        "the peer's machine is not known yet, so persistent forward {0} cannot be pinned to \
         it; retry once the peer is discovered, or add it as ephemeral"
    )]
    Unpinned(String),
    /// The forward would not load back (e.g. a non-loopback or hostname
    /// target), so it is refused rather than written: one bad record would
    /// otherwise make the whole file fail closed at the next start.
    #[error("forward cannot be persisted: {0}")]
    Invalid(String),
}

impl ForwardStoreError {
    /// Memory and disk already show this change. Do not roll it back.
    #[must_use]
    pub(crate) fn durability_unconfirmed(&self) -> bool {
        matches!(self, Self::Unconfirmed(_))
    }
}

/// One persisted forward (the ADR-0074 §2 record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRecord {
    /// Record id: the bound local address as text (the `DELETE
    /// /forwards/:local_addr` key).
    pub id: String,
    /// Bound loopback address.
    pub local_addr: SocketAddr,
    /// Canonical kind-prefixed name, or `None` for a hex peer.
    pub name: Option<String>,
    /// Agent or machine target.
    pub kind: NameKind,
    /// The agent streams open to.
    pub pinned_agent_id: AgentId,
    /// The machine every stream must reach.
    pub pinned_machine_id: MachineId,
    /// Numeric loopback host on the peer (e.g. `127.0.0.1`, `::1`).
    pub target_host: String,
    /// Target port on the peer.
    pub target_port: u16,
}

impl ForwardRecord {
    /// The record for `spec`: `Ok(None)` for an ephemeral forward.
    ///
    /// # Errors
    /// [`ForwardStoreError::Unpinned`] for a persistent forward without a
    /// pinned machine.
    pub fn from_spec(spec: &ForwardSpec) -> Result<Option<Self>, ForwardStoreError> {
        if !spec.persistent {
            return Ok(None);
        }
        let pinned_machine_id = spec
            .pinned_machine
            .ok_or_else(|| ForwardStoreError::Unpinned(spec.local_addr.to_string()))?;
        Ok(Some(Self {
            id: spec.local_addr.to_string(),
            local_addr: spec.local_addr,
            name: spec.name.clone(),
            kind: spec.kind,
            pinned_agent_id: spec.peer_agent,
            pinned_machine_id,
            target_host: spec.target_host.clone(),
            target_port: spec.target_port,
        }))
    }

    /// The forward this record describes (persistent, pinned).
    #[must_use]
    pub fn to_spec(&self) -> ForwardSpec {
        ForwardSpec {
            local_addr: self.local_addr,
            peer_agent: self.pinned_agent_id,
            target_host: self.target_host.clone(),
            target_port: self.target_port,
            name: self.name.clone(),
            kind: self.kind,
            pinned_machine: Some(self.pinned_machine_id),
            persistent: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordJson {
    id: String,
    local_addr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    kind: NameKind,
    pinned_agent_id: String,
    pinned_machine_id: String,
    target_host: String,
    target_port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardsFile {
    version: u32,
    forwards: Vec<RecordJson>,
}

fn decode32(field: &str, raw: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(raw, &mut out).map_err(|e| format!("{field}: {e}"))?;
    Ok(out)
}

impl RecordJson {
    fn from_record(r: &ForwardRecord) -> Self {
        Self {
            id: r.id.clone(),
            local_addr: r.local_addr.to_string(),
            name: r.name.clone(),
            kind: r.kind,
            pinned_agent_id: hex::encode(r.pinned_agent_id.as_bytes()),
            pinned_machine_id: hex::encode(r.pinned_machine_id.as_bytes()),
            target_host: r.target_host.clone(),
            target_port: r.target_port,
        }
    }

    /// Validate every field; any violation refuses the whole file.
    fn into_record(self) -> Result<ForwardRecord, String> {
        let local_addr: SocketAddr = self
            .local_addr
            .parse()
            .map_err(|e| format!("local_addr {:?}: {e}", self.local_addr))?;
        if !local_addr.ip().is_loopback() || local_addr.port() == 0 {
            return Err(format!(
                "local_addr {local_addr} must be a bound loopback address"
            ));
        }
        if self.id != local_addr.to_string() {
            return Err(format!(
                "record id {:?} does not match local_addr {local_addr}",
                self.id
            ));
        }
        // Re-validate the target exactly as the inbound side will.
        super::resolve_loopback_target(&self.target_host, self.target_port)
            .map_err(|e| format!("{}: {e}", self.id))?;
        if let Some(name) = &self.name {
            let parsed = NameRef::parse(name).map_err(|e| format!("{}: {e}", self.id))?;
            if parsed.kind != Some(self.kind) || parsed.canonical(self.kind) != *name {
                return Err(format!(
                    "{}: name {name:?} is not the canonical {} name",
                    self.id,
                    self.kind.as_str()
                ));
            }
        } else if self.kind == NameKind::Machine {
            return Err(format!("{}: a machine forward needs its name", self.id));
        }
        Ok(ForwardRecord {
            id: self.id,
            local_addr,
            name: self.name,
            kind: self.kind,
            pinned_agent_id: AgentId(decode32("pinned_agent_id", &self.pinned_agent_id)?),
            pinned_machine_id: MachineId(decode32("pinned_machine_id", &self.pinned_machine_id)?),
            target_host: self.target_host,
            target_port: self.target_port,
        })
    }
}

/// Only a record the loader accepts back may be written: one bad record
/// would otherwise make the whole file fail closed at the next start.
fn validate(record: &ForwardRecord) -> Result<(), ForwardStoreError> {
    RecordJson::from_record(record)
        .into_record()
        .map(|_| ())
        .map_err(ForwardStoreError::Invalid)
}

fn decode_file(bytes: &[u8]) -> Result<Vec<ForwardRecord>, String> {
    let file: ForwardsFile = serde_json::from_slice(bytes).map_err(|e| format!("decode: {e}"))?;
    if file.version != STORE_VERSION {
        return Err(format!(
            "unsupported forwards.json version {}",
            file.version
        ));
    }
    if file.forwards.len() > MAX_FORWARDS {
        return Err("forwards.json exceeds its size bound".into());
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(file.forwards.len());
    for record in file.forwards {
        let record = record.into_record()?;
        if !seen.insert(record.id.clone()) {
            return Err(format!("duplicate forward id {}", record.id));
        }
        out.push(record);
    }
    Ok(out)
}

/// Persistent forwards (`<data_dir>/forwards.json`). All mutations are
/// serialised under one lock held across the durable write. A failure
/// before the rename changes nothing. A failure after the rename keeps the
/// new set in memory (it matches the file) and reports
/// [`ForwardStoreError::Unconfirmed`] until a later write confirms the
/// parent-directory fsync. An identical retry must not report success
/// while that confirmation is still pending.
///
/// `ops` is a second lock, held by restore, add, and remove together. The
/// record lock above covers one write; `ops` covers the gap between reading
/// the records and binding a listener, so a delete in that gap cannot be
/// overwritten by a stale restore.
#[derive(Debug)]
pub struct ForwardStore {
    path: Option<PathBuf>,
    state: tokio::sync::Mutex<Vec<ForwardRecord>>,
    load_error: Option<String>,
    ops: Arc<tokio::sync::Mutex<()>>,
    /// Set when a write crossed the rename but parent-dir fsync failed.
    /// Cleared only by a successful durable persist. While set, [`Self::commit`]
    /// re-attempts the write even when the mutate is a no-op.
    pending_durability: std::sync::atomic::AtomicBool,
    /// Staged by the post-rename callback; drained into [`Self::state`]
    /// under the lock so a cancelled persist await cannot lose the
    /// advanced disk state.
    install_slot: std::sync::Mutex<Option<Vec<ForwardRecord>>>,
    /// Test seam: restore notifies `entered` after it has copied the records
    /// and waits on `release`, still holding `ops`. One shot.
    #[cfg(test)]
    restore_pause: std::sync::Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}

/// Records copied for restore, with `ops` still held so add and remove wait.
pub(crate) struct RestoreSession {
    _ops: tokio::sync::OwnedMutexGuard<()>,
    pub(crate) records: Vec<ForwardRecord>,
}

impl ForwardStore {
    /// An empty in-memory store (tests, or no data dir).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            state: tokio::sync::Mutex::new(Vec::new()),
            load_error: None,
            ops: Arc::new(tokio::sync::Mutex::new(())),
            pending_durability: std::sync::atomic::AtomicBool::new(false),
            install_slot: std::sync::Mutex::new(None),
            #[cfg(test)]
            restore_pause: std::sync::Mutex::new(None),
        }
    }

    /// Hold `ops` for one restore, add, or remove. The guard owns its
    /// `Arc`, so the caller can keep it across later `&self` borrows.
    pub(crate) async fn lock_ops(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.ops).lock_owned().await
    }

    /// Copy the records and keep `ops` until the session is dropped.
    ///
    /// # Errors
    /// [`ForwardStoreError::Unusable`] when the file did not load. The
    /// lock is not held in that case.
    pub(crate) async fn begin_restore(&self) -> Result<RestoreSession, ForwardStoreError> {
        let ops = self.lock_ops().await;
        let records = self.records().await?;
        #[cfg(test)]
        self.pause_restore_if_armed().await;
        Ok(RestoreSession { _ops: ops, records })
    }

    /// `Some` when `ops` is free. Tests use this to prove restore still holds
    /// the lifecycle lock after it has copied the records.
    #[cfg(test)]
    pub(crate) fn ops_try_lock(&self) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        Arc::clone(&self.ops).try_lock_owned().ok()
    }

    /// Arm the one-shot pause inside [`Self::begin_restore`].
    #[cfg(test)]
    pub(crate) fn arm_restore_pause(
        &self,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    ) {
        *self
            .restore_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((entered, release));
    }

    #[cfg(test)]
    async fn pause_restore_if_armed(&self) {
        let gate = self
            .restore_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((entered, release)) = gate {
            entered.notify_one();
            release.notified().await;
        }
    }

    /// The store path inside `data_dir`.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(FORWARDS_STORE_FILE)
    }

    /// Load `path` (missing ⇒ empty; unreadable/malformed ⇒ fail closed).
    ///
    /// A readable file is confirmed the way [`crate::names::NameStore::load`]
    /// confirms `names.json`: fsync the file, then fsync its directory. A
    /// previous process may have published the file and then failed that
    /// directory sync. The records still load, and durability stays pending
    /// so a later identical [`Self::remember`] retries the sync instead of
    /// reporting success.
    pub async fn load(path: PathBuf) -> Self {
        let mut store = Self::in_memory();
        store.path = Some(path.clone());
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return store,
            Err(e) => {
                store.load_error = Some(format!("read {}: {e}", path.display()));
                return store;
            }
        };
        match decode_file(&bytes) {
            Ok(records) => {
                store.state = tokio::sync::Mutex::new(records);
                if let Err(error) = crate::storage::confirm_published_durability(&path).await {
                    tracing::warn!(
                        "forward store at {} is loaded but directory sync is not confirmed: {error}",
                        path.display()
                    );
                    store
                        .pending_durability
                        .store(true, std::sync::atomic::Ordering::Release);
                }
            }
            Err(e) => {
                let e = format!("{}: {e}", path.display());
                tracing::warn!("forward store unreadable, restoring no forwards: {e}");
                store.load_error = Some(e);
            }
        }
        store
    }

    /// Why the on-disk store is not in force, if it is not.
    #[must_use]
    pub fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    fn usable(&self) -> Result<(), ForwardStoreError> {
        match &self.load_error {
            Some(e) => Err(ForwardStoreError::Unusable(e.clone())),
            None => Ok(()),
        }
    }

    /// Write `records` atomically (mode 0600). `on_renamed` runs when the
    /// new bytes are visible (after rename, before parent-dir fsync).
    async fn persist_with_install(
        &self,
        records: &[ForwardRecord],
        on_renamed: impl FnOnce() + Send,
    ) -> Result<(), crate::storage::DurableWriteError> {
        let Some(path) = &self.path else {
            on_renamed();
            return Ok(());
        };
        let file = ForwardsFile {
            version: STORE_VERSION,
            forwards: records.iter().map(RecordJson::from_record).collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| {
            crate::storage::DurableWriteError::BeforeRename(std::io::Error::other(format!(
                "encode: {e}"
            )))
        })?;
        crate::storage::write_private_bytes_durable_typed_after_rename(path, bytes, on_renamed)
            .await
            .map_err(|e| e.with_path(path))
    }

    fn drain_install_slot(&self, guard: &mut Vec<ForwardRecord>) {
        if let Ok(mut slot) = self.install_slot.lock() {
            if let Some(next) = slot.take() {
                *guard = next;
            }
        }
    }

    async fn lock_state(&self) -> tokio::sync::MutexGuard<'_, Vec<ForwardRecord>> {
        let mut guard = self.state.lock().await;
        self.drain_install_slot(&mut guard);
        guard
    }

    /// Apply `mutate` to a copy, persist it, then commit.
    ///
    /// Success installs the new set. `BeforeRename` keeps the old memory
    /// (disk unchanged). `AfterRename` stages the new set in
    /// [`Self::install_slot`] inside the rename callback (cancel-safe),
    /// drains it into the lock, then returns
    /// [`ForwardStoreError::Unconfirmed`]. A later no-op mutate retries
    /// the write while durability is pending — it must not report success
    /// until a parent-directory fsync succeeds.
    async fn commit(
        &self,
        mutate: impl FnOnce(&mut Vec<ForwardRecord>) -> Result<bool, ForwardStoreError>,
    ) -> Result<bool, ForwardStoreError> {
        use std::sync::atomic::Ordering;
        self.usable()?;
        let mut guard = self.lock_state().await;
        let mut next = guard.clone();
        let changed = mutate(&mut next)?;
        if changed {
            let to_install = next.clone();
            let slot = &self.install_slot;
            let pending = &self.pending_durability;
            match self
                .persist_with_install(&next, move || {
                    if let Ok(mut staged) = slot.lock() {
                        *staged = Some(to_install);
                    }
                    pending.store(true, Ordering::Release);
                })
                .await
            {
                Ok(()) => {
                    self.drain_install_slot(&mut guard);
                    self.pending_durability.store(false, Ordering::Release);
                }
                Err(e) if e.crossed_rename() => {
                    self.drain_install_slot(&mut guard);
                    return Err(ForwardStoreError::Unconfirmed(e.to_string()));
                }
                Err(e) => {
                    let _ = self.install_slot.lock().map(|mut staged| staged.take());
                    return Err(ForwardStoreError::Write(format!("write {e}")));
                }
            }
        } else if self.pending_durability.load(Ordering::Acquire) {
            let pending = &self.pending_durability;
            let held = guard.clone();
            match self
                .persist_with_install(&held, || {
                    pending.store(true, Ordering::Release);
                })
                .await
            {
                Ok(()) => {
                    self.pending_durability.store(false, Ordering::Release);
                }
                Err(e) if e.crossed_rename() => {
                    return Err(ForwardStoreError::Unconfirmed(e.to_string()));
                }
                Err(e) => return Err(ForwardStoreError::Write(format!("write {e}"))),
            }
        }
        Ok(changed)
    }

    /// Every persisted forward.
    ///
    /// # Errors
    /// [`ForwardStoreError::Unusable`] when the file did not load.
    pub async fn records(&self) -> Result<Vec<ForwardRecord>, ForwardStoreError> {
        self.usable()?;
        Ok(self.lock_state().await.clone())
    }

    /// Whether [`Self::remember`] would accept `spec`, without writing — so
    /// a caller can refuse a forward before binding its port.
    ///
    /// # Errors
    /// `Unusable`, `Unpinned` or `Invalid`.
    pub fn check(&self, spec: &ForwardSpec) -> Result<(), ForwardStoreError> {
        let Some(mut record) = ForwardRecord::from_spec(spec)? else {
            return Ok(());
        };
        // Before binding, a requested `:0` has no port yet; the kernel
        // assigns one, so validate everything else.
        if record.local_addr.port() == 0 {
            record.local_addr.set_port(1);
            record.id = record.local_addr.to_string();
        }
        validate(&record)?;
        self.usable()
    }

    /// Persist `spec` unless it is ephemeral, replacing any record with the
    /// same id. Returns whether a record was written.
    ///
    /// # Errors
    /// `Unusable`, `Unpinned`, `Invalid`, `Full`, `Write` (disk unchanged),
    /// or `Unconfirmed` (the new record is in memory and on disk; durability
    /// is not confirmed).
    pub async fn remember(&self, spec: &ForwardSpec) -> Result<bool, ForwardStoreError> {
        let Some(record) = ForwardRecord::from_spec(spec)? else {
            return Ok(false);
        };
        validate(&record)?;
        self.commit(move |records| {
            if let Some(held) = records.iter_mut().find(|held| held.id == record.id) {
                if *held == record {
                    return Ok(false);
                }
                *held = record;
                return Ok(true);
            }
            if records.len() >= MAX_FORWARDS {
                return Err(ForwardStoreError::Full);
            }
            records.push(record);
            Ok(true)
        })
        .await
    }

    /// Delete the record bound to `local_addr`. Returns whether one existed.
    ///
    /// # Errors
    /// `Unusable`, `Write` (disk unchanged), or `Unconfirmed` (the record is
    /// already gone from memory and from the renamed file; durability is
    /// not confirmed). A retry while confirmation is pending does not
    /// report success.
    pub async fn forget(&self, local_addr: SocketAddr) -> Result<bool, ForwardStoreError> {
        let id = local_addr.to_string();
        self.commit(move |records| {
            let before = records.len();
            records.retain(|record| record.id != id);
            Ok(records.len() != before)
        })
        .await
    }
}

/// Decide whether a persisted forward comes back up (ADR-0074 §2).
///
/// `resolution` is the record's name re-resolved through the name store
/// (where the name's pin applies); it is ignored for a hex record, which
/// comes back on its pinned ids. The forward comes up only when the name
/// still denotes exactly the pinned agent (and, for a machine name, the
/// pinned machine). Otherwise it stays down with `Err(reason)`: a pin
/// mismatch or different ids give `name_changed`, anything else the name
/// error's code. It is never retargeted.
///
/// # Errors
/// The reason the forward stays down.
pub fn restore_decision(
    record: &ForwardRecord,
    resolution: Option<Result<Resolved, NameError>>,
) -> Result<ForwardSpec, String> {
    let Some(name) = &record.name else {
        return Ok(record.to_spec());
    };
    let resolved = match resolution {
        Some(Ok(resolved)) => resolved,
        Some(Err(e @ NameError::PinMismatch { .. })) => return Err(format!("{NAME_CHANGED}: {e}")),
        Some(Err(e)) => return Err(format!("{}: {e}", e.code())),
        None => return Err(format!("unknown_name: {name} was not re-resolved")),
    };
    let hex_opt = |id: Option<[u8; 32]>| id.map_or_else(|| "none".to_string(), hex::encode);
    let same_agent = resolved.agent_id == Some(record.pinned_agent_id);
    let same_machine =
        record.kind != NameKind::Machine || resolved.machine_id == Some(record.pinned_machine_id);
    if resolved.kind != record.kind || !same_agent || !same_machine {
        return Err(format!(
            "{NAME_CHANGED}: {name} now resolves to {} agent {} machine {}, but the forward \
             is pinned to agent {} machine {}; re-add the forward to re-pin",
            resolved.kind.as_str(),
            hex_opt(resolved.agent_id.map(|a| a.0)),
            hex_opt(resolved.machine_id.map(|m| m.0)),
            hex::encode(record.pinned_agent_id.as_bytes()),
            hex::encode(record.pinned_machine_id.as_bytes()),
        ));
    }
    Ok(record.to_spec())
}

#[cfg(test)]
mod tests;
