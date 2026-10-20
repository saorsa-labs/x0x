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
//! [`crate::storage::write_private_bytes_durable`] (temp file, fsync, mode
//! `0600`, atomic rename) — the same pattern as `names.json`. A missing
//! file is an empty store; an unreadable or malformed one leaves the store
//! refusing every operation, and it is never overwritten.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
    /// Persisting failed; nothing changed.
    #[error("forward store write failed: {0}")]
    Write(String),
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
/// serialised under one lock held across the durable write; a failed write
/// changes nothing.
#[derive(Debug)]
pub struct ForwardStore {
    path: Option<PathBuf>,
    state: tokio::sync::Mutex<Vec<ForwardRecord>>,
    load_error: Option<String>,
}

impl ForwardStore {
    /// An empty in-memory store (tests, or no data dir).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            state: tokio::sync::Mutex::new(Vec::new()),
            load_error: None,
        }
    }

    /// The store path inside `data_dir`.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(FORWARDS_STORE_FILE)
    }

    /// Load `path` (missing ⇒ empty; unreadable/malformed ⇒ fail closed).
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
            Ok(records) => store.state = tokio::sync::Mutex::new(records),
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

    async fn persist(&self, records: &[ForwardRecord]) -> Result<(), ForwardStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = ForwardsFile {
            version: STORE_VERSION,
            forwards: records.iter().map(RecordJson::from_record).collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| ForwardStoreError::Write(format!("encode: {e}")))?;
        crate::storage::write_private_bytes_durable(path, bytes)
            .await
            .map_err(|e| ForwardStoreError::Write(format!("{}: {e}", path.display())))
    }

    /// Every persisted forward.
    ///
    /// # Errors
    /// [`ForwardStoreError::Unusable`] when the file did not load.
    pub async fn records(&self) -> Result<Vec<ForwardRecord>, ForwardStoreError> {
        self.usable()?;
        Ok(self.state.lock().await.clone())
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
    /// `Unusable`, `Unpinned`, `Invalid`, `Full` or `Write`; on error nothing
    /// changed.
    pub async fn remember(&self, spec: &ForwardSpec) -> Result<bool, ForwardStoreError> {
        let Some(record) = ForwardRecord::from_spec(spec)? else {
            return Ok(false);
        };
        validate(&record)?;
        self.usable()?;
        let mut guard = self.state.lock().await;
        let mut next = guard.clone();
        if let Some(held) = next.iter_mut().find(|r| r.id == record.id) {
            *held = record;
        } else {
            if next.len() >= MAX_FORWARDS {
                return Err(ForwardStoreError::Full);
            }
            next.push(record);
        }
        self.persist(&next).await?;
        *guard = next;
        Ok(true)
    }

    /// Delete the record bound to `local_addr`. Returns whether one existed.
    ///
    /// # Errors
    /// `Unusable` or `Write`; on error nothing changed.
    pub async fn forget(&self, local_addr: SocketAddr) -> Result<bool, ForwardStoreError> {
        self.usable()?;
        let mut guard = self.state.lock().await;
        let id = local_addr.to_string();
        if !guard.iter().any(|r| r.id == id) {
            return Ok(false);
        }
        let next: Vec<ForwardRecord> = guard.iter().filter(|r| r.id != id).cloned().collect();
        self.persist(&next).await?;
        *guard = next;
        Ok(true)
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
